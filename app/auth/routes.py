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
from app.active_connect.active_connect_utils import get_management_api, authenticate_user, \
    create_session_token, decode_session_token, end_session
from Activeconnect.management_api import ManagementAPIResult
from Activeconnect.session import Session as ActiveConnect_Session
from itsdangerous import JSONWebSignatureSerializer, BadSignature


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm(request.values, session_token="ABCD")
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None:
            flash(_('Invalid username'))
            return redirect(url_for('auth.login'))

        ac_session, user_id = decode_session_token(form.session_token.data)

        if ac_session is not None and ac_session.active and user_id == user.id:
            session['ac_session']=form.session_token.data
            login_user(user, remember=False)
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('main.index')
            return redirect(next_page)
    return render_template('auth/login.html', title=_('Sign In'), form=form, no_status_checks=True)


@bp.route('/start_authentication/<username>', methods=["POST"])
def start_authentication(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        return jsonify({"status": False, "message": "User {} not found.".format(username)})

    ac_session = authenticate_user(user.active_connect_id)

    if ac_session.failed:
        return jsonify({"status": False, "message": "Login Failed."})
    else:

        session_token = create_session_token(ac_session, user.id)
        return jsonify({"status": True, "token": session_token.decode('UTF-8')})


@bp.route('/session_status', methods=["GET"])
def session_status():
    if current_user is not None and current_user.is_authenticated:
        return jsonify({"status": "active"})

    return jsonify({"status": "closed"})

@bp.route('/logout')
def logout():
    logout_user()
    end_session()

    return redirect(url_for('main.index'))

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)

        # Register the user with Activeconnect.
        manager = get_management_api()
        add_user_result = manager.add_user(user.active_connect_id)

        if add_user_result == ManagementAPIResult.success:
            db.session.add(user)
            db.session.commit()
            flash(_('Congratulations, you are now a registered user!'))
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
    user = User.query.filter(User.id == user_id).first_or_404()

    # Create the activeconnect manager object.
    manager = get_management_api()

    # Get a registration link for the user
    registration_link = manager.get_registration_link(user_id = user.active_connect_id, display_name=user.username)
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
