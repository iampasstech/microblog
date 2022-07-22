# Welcome to Microblog!
This is a fork of the Miguel Grinberg's [Flask Mega-Tutorial](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world).
The application has been modified to use [IAMPASS](https://iampass.com) for user authentication.
Full instructions for running the application can be found on [Flask Mega-Tutorial Page](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world).

The application makes us of [Flask-Login](https://flask-login.readthedocs.io/en/latest/) for user authentication.
The application uses the [IAMPASS python module](https://pypi.org/project/IAMPASS/) to communicate with the IAMPASS service.
This application has been configured to use an example IAMPASS client application.
In order to use it with your own IAMPASS client application you will need to:
* Create an [IAMPASS account](https://main.iam-api.com/register)
* Create an IAMPASS client application.
* Modify config.py
```python
class Config(object):
...
    IAMPASS_APPLICATION_ID = "MY APPLICATION ID"
    IAMPASS_APPLICATION_SECRET = "MY APPLICATION SECRET"
```

## Running the app
* In a terminal window, change to the repo directory
```
$ cd CLONE_DIR
```
* Create a virtual environment
```
$ python3 -m venv venv
```
* Activate the virtual environment
```
$ source venv/bin/activate
```
* Install packages
```
$ pip install -r requirements.txt
```
* Make sure the database is up to data
```
$ flask db upgrade
```
* Run the application
```
$ flask run
```

## User Registration
Before a user can be authenticated using IAMPASS, they must be registered with the IAMPASS system.
IAMPASS only requires a string token to identify a user of a client application.
The value of this token is entirely up to the author of the client application.
The recommended approach is to use a random token that is associated with the client application's user.
Using this system means that IAMPASS stores no information that can be linked back to the user of the client application.
This version of the Microblog application modifies the User model to include the field iampass_id. 
This field is initialized with a random string that is used to identify the user to IAMPASS.

```python
# app/auth/routes.py
@bp.route('/register', methods=['GET', 'POST'])
def register():
    # This is where we register users.
    # In the original version of the Microblog application, the user is just registered and the user
    # is redirected to the login page.
    # Using IAMPASS requires that we register the user with IAMPASS, then render
    # a page with information that allows them to register their mobile device with IAMPASS.
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)

        # Register the user with IAMPASS.
        manager = get_management_api()
        add_user_result = manager.add_user(user.iampass_id)

        if add_user_result == ManagementAPIResult.success:
            # We don't add the user to our database until they have been registered with IAMPASS.
            db.session.add(user)
            db.session.commit()
            flash(_('Congratulations, you are now a registered user!'))
            # Now redirect to the device registration page.
            return redirect(url_for('auth.register_device', user_id=user.id))
        else:
            # We failed to register the user so just show the page again.
            if add_user_result == ManagementAPIResult.user_exists:
                # User already exists
                flash('User already exists')
            else:
                # User failed
                flash('Failed to add user')
            return redirect(url_for('auth.register'))

    return render_template('auth/register.html', title=_('Register'),
                           form=form, no_status_checks=True)

```
Once a user has been registerd with IAMPASS the User is saved to the database and the app redirects to the
**/auth/register_device** route.
```python
# app/auth/routes.py
@bp.route('/register_device/<user_id>', methods=['GET'])
def register_device(user_id):
    # This route displays a page with a QR code that the user can scan with their mobile device to register it
    # with IAMPASS.
    user = User.query.filter(User.id == user_id).first_or_404()

    # Create the IAMPASS manager object.
    manager = get_management_api()

    # Get a registration link for the user
    registration_link = manager.get_registration_link(user_id = user.iampass_id, display_name=user.username)
    return render_template('auth/register_device.html', reg_link = registration_link, no_status_checks=True)

```
This route uses the IAMPASS management API to get a link that can be used by the user to register their mobile device.
In this case the page renders the link as a QR code that can be scanned with the IAMPASS Mobile App.

## Authentication
When the user clicks the 'Sign In' button on the login form, Javascript is used to call the **/start_authentication/username** route.
```javascript
// app/templates/auth/login.html
        function callAuthenticationAPI() {
            let username = $("#username").val();
            let url = "{{ url_for('auth.start_authentication',username=username) }}" + username;

            showAuthenticating(true);


            // Call the status url
            $.ajax({
                type: "POST",
                url: url,
                contentType: "application/json; charset=utf-8",
                dataType: "json",
                success: function (data) {
                    console.debug(data);
                    showAuthenticating(false);

                    if (data.status == true) {

                        console.log("authenticated");
                        let token = data.token;
                        $("#session_token").val(token);
                        $("form").submit();
                    } else {
                        console.log("failed " + data.message);
                        showError(data.message);
                        let flasher = $("#flasher");
                    }
                },
                error: function (jqXHR, exception) {
                    showAuthenticating(false);
                    showError("Login Failed");
                }
            })

        }
```
If authentication is successful **start_authentication** route returns IAMPASS session information.
This data is stored in a hidden form field and the form is submitted (POST /login).

Inside the **login** route Flask-Login is used to 'login' the user. In addition the IAMPASS session information is written to Flask's session instance.

```python
# app/auth/routes.py
from app.iampass.iampass import get_management_api, authenticate_user,
    create_session_token, decode_session_token, end_session

...


@bp.route('/login', methods=['GET', 'POST'])
def login():
    # When the client posts to this route IAMPASS authentication has completed.
    # Instead of checking a password we get the IAMPASS session information from a
    # hidden form element and check it.
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm(request.values, session_token="ABCD")
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None:
            flash(_('Invalid username'))
            return redirect(url_for('auth.login'))

        # The information for the IAMPASS session is stored in the hidden session_token field of the form.
        # Get the session data and check that the user has been authenticated.
        ip_session, user_id = decode_session_token(form.session_token.data)

        if ip_session is not None and ip_session.active and user_id == user.id:
            # Store the session information. User.is_authenticated will use this when it is called by
            # flask-login during execution of the @login_required decorator.
            session['ip_session'] = form.session_token.data
            login_user(user, remember=False)
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('main.index')
            return redirect(next_page)

    # Render the login form. We set no_status_checks to True so that the login form does not redirect
    # us to the logout route by checking the status of a session that has not been created.
    return render_template('auth/login.html', title=_('Sign In'), form=form, no_status_checks=True)

```
## Checking Login Status
Flask-Login used the ```@login_required``` decorator to protect resources. 
The ```login_required``` decorator calls User.is_authenticated to determine if the user is authenticated.
The standard implementation uses the ```UserMixin``` class to provide this property.
In order to use IAMPASS the ```User``` model is changed to call IAMPASS to get the status of the session.
```python
# app/models.py
class User(UserMixin, PaginatedAPIMixin, db.Model):
    # This is a random string used to identify this user to iampass.
    iampass_id = db.Column(db.String(32), index=True, unique=True)

    @property
    def is_authenticated(self):
        # Call the is_user_authenticated helper (app/iampass/iampass_utils.py)
        return is_user_authenticated(self.id)
```
## Session Monitoring
An IAMPASS session can be closed by the user clicking the 'logout' button but can also be closed remotely:
* The user (or an administrator) can end the session from the IAMPASS Mobile App.
* The session may be closed because the user is no longer present.
Traditionally Flask-Login is used to check login status when a resource is requested.
In order to respond to session status changes this application will periodically check the session status and if it is no longer active will:
* log the user out
* redirect to the login page.

This functionality is provided by Javascript code in app/templates/base.html (the base for all templates in the application).
The no_status_checks template parameter is used to prevent templates that do not need to check status from doing so (/login).
To disable status checking pass ```no_status_checks=True``` when calling ```render_template```.
```javascript
    {% if not no_status_checks %}

        <script>
            var statusChecker = null;

            $(document).ready(function () {
                console.log("ready!");
                statusChecker = setTimeout(callStatusAPI, 1000);
            });


            function callStatusAPI() {
                let url = "{{ url_for("auth.session_status") }}";


                // Call the status url
                $.ajax({
                    type: "GET",
                    url: url,
                    contentType: "application/json; charset=utf-8",
                    dataType: "json",
                    success: function (data) {
                        console.debug(data);

                        if (data.status == 'active') {
                            console.log("authenticated");
                            statusChecker = setTimeout(callStatusAPI, 1000);
                        } else {
                            console.log("logged out " + data.message);
                            window.location.href = '{{ url_for("auth.logout") }}';
                        }
                    }
                })

            }
        </script>
    {% endif %}

```