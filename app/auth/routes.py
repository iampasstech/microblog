from flask import render_template, redirect, url_for, flash, request, jsonify, current_app, session
from werkzeug.urls import url_parse
from flask_login import login_user, logout_user, current_user
from flask_babel import _
from app import db
from app.auth import bp
from app.auth.forms import LoginForm, RegistrationForm, \
    ResetPasswordRequestForm, ResetPasswordForm
from app.models import User
from app.auth.email import send_password_reset_email
from app.iampass.iampass_utils import get_management_api, authenticate_user, \
    create_session_token, decode_session_token, end_session
from IAMPASS.management_api import ManagementAPIResult


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
            session['ip_session']=form.session_token.data
            login_user(user, remember=False)
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('main.index')
            return redirect(next_page)

    # Render the login form. We set no_status_checks to True so that the login form does not redirect
    # us to the logout route by checking the status of a session that has not been created.
    return render_template('auth/login.html', title=_('Sign In'), form=form, no_status_checks=True)


@bp.route('/start_authentication/<username>', methods=["POST"])
def start_authentication(username):
    # This is where IAMPASS authentication is triggered.
    # This route is called by JS code in the login form when the user clicks the 'Sign In' button.
    # <username> is the value obtained from the username form element.
    # When the login form gets the response from this route it will POST to /login.

    # Check that the user exists.
    user = User.query.filter_by(username=username).first()
    if user is None:
        return jsonify({"status": False, "message": "User {} not found.".format(username)})

    # Start the IAMPASS authentication process.
    # This method will not return until the process completes.
    ip_session = authenticate_user(user.iampass_id)

    # If authentication failed, just return JSON with a generic error message in it.
    if ip_session.failed:
        return jsonify({"status": False, "message": "Login Failed."})
    else:
        # Authentication was successful, so create a token using the user's id and the session information.
        # Then return it in the response BODY
        session_token = create_session_token(ip_session, user.id)
        return jsonify({"status": True, "token": session_token.decode('UTF-8')})


@bp.route('/session_status', methods=["GET"])
def session_status():
    # If we want to have pages that respond to sessions changing state (remote logout) we need a route
    # to get the current status.
    # This route is called by a timer in the JS code included in base.html.
    if current_user is not None and current_user.is_authenticated:
        return jsonify({"status": "active"})

    return jsonify({"status": "closed"})


@bp.route('/logout')
def logout():
    # Logs out the user and closes the IAMPASS session.
    logout_user()
    end_session()

    return redirect(url_for('main.index'))


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

@bp.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash(
            _('Check your email for the instructions to reset your password'))
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password_request.html',
                           title=_('Reset Password'), form=form, no_status_checks=True)


@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('main.index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash(_('Your password has been reset.'))
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form, no_status_checks=True)
