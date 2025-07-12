import os
import logging

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from utils import login_required, admin_required, allowed_file

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = "your_secret_key"  # change this to a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:mekonipata654123@localhost/skillswap'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configuration
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 🔐 Password handling
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)



    

class UserProfile(db.Model):
    __tablename__ = 'user_profile'

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    bio = db.Column(db.Text)
    location = db.Column(db.String(100))
    # ... add other fields as needed

    # Relationship to the User
    user = db.relationship('User', backref='profile')


class Skill(db.Model):
    __tablename__ = 'skill'

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # ✅ must be present

    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # e.g., 'offer' or 'want'

    # ✅ Relationship to User
    user = db.relationship('User', backref='skill')




class SwapRequest(db.Model):
    __tablename__ = 'swap_requests'
    id = db.Column(db.Integer, primary_key=True)
    provider_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    offered_skill = db.Column(db.String(100))
    wanted_skill = db.Column(db.String(100))
    message = db.Column(db.Text)
    status = db.Column(db.Enum('pending', 'accepted', 'rejected', 'completed'), default='pending')
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    completed_at = db.Column(db.DateTime, default=None)


    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    provider_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Rating(db.Model):
    __tablename__ = 'ratings'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # <- Add this
    category = db.Column(db.String(100), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='ratings')  # Optional: add relationship


@app.route('/')
def index():
    """Homepage showing recent activity and platform overview"""
    recent_swaps = []
    if 'user_id' in session:
        user_id = session['user_id']

        recent_swaps = SwapRequest.query.filter(
            (SwapRequest.requester_id == user_id) | (SwapRequest.provider_id == user_id)
        ).order_by(SwapRequest.created_at.desc()).limit(5).all()

        # Optional: Add user info for requester and provider if needed in template
        for swap in recent_swaps:
            swap.requester = User.query.get(swap.requester_id)
            swap.provider = User.query.get(swap.provider_id)

    return render_template('index.html', recent_swaps=recent_swaps)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validation
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
            return render_template('register.html')

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return render_template('register.html')

        # ✅ This will now work
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
        session['username'] = username

        flash('Registration successful! Welcome to Skill Swap Platform.', 'success')
        return redirect(url_for('profile'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin  # assuming 'is_admin' is a column in your User model

            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    user = User.query.get(session['user_id'])
    profile = UserProfile.query.filter_by(user_id=user.id).first()

    skill = Skill.query.filter_by(user_id=user.id).all()
    offered_skill = [s.name for s in skill if s.type == 'offered']
    wanted_skill = [s.name for s in skill if s.type == 'wanted']

    ratings = Rating.query.filter_by(user_id=user.id).all()
    avg_rating = sum(r.rating for r in ratings) / len(ratings) if ratings else 0

    return render_template(
        'profile.html',
        user=user,
        profile=profile,
        offered_skill=offered_skill,
        wanted_skill=wanted_skill,
        ratings=ratings,
        avg_rating=avg_rating
    )


@app.route('/browse')
def browse():
    search_query = request.args.get('search', '').strip()
    skill_filter = request.args.get('skill', '').strip()

    # Get all unique skill from the database for the dropdown
    all_skill = db.session.query(Skill.name).distinct().all()
    all_skill = [skill[0] for skill in all_skill]  # unpack from tuple

    # Start with all users
    query = db.session.query(UserProfile).join(User).outerjoin(Skill)

    if search_query:
        query = query.filter(User.username.ilike(f"%{search_query}%"))

    if skill_filter:
        query = query.filter(Skill.name.ilike(f"%{skill_filter}%"))

    profiles = query.distinct().all()

    # Create the `users` list in the format expected by your template
    users = []
    for profile in profiles:
        user = profile.user
        offered_skill = [s.name for s in user.skill if s.type == 'offered']
        wanted_skill = [s.name for s in user.skill if s.type == 'wanted']
        rating = user.get_average_rating() if hasattr(user, 'get_average_rating') else 0

        users.append({
            'user': user,
            'skill': {
                'offered': offered_skill,
                'wanted': wanted_skill,
            },
            'rating': rating
        })

    return render_template(
        'browse.html',
        users=users,
        search_query=search_query,
        skill_filter=skill_filter,
        all_skill=all_skill
    )




@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash("You must be logged in.", "warning")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    # Try to get profile, or create it
    profile = UserProfile.query.filter_by(user_id=user.id).first()
    if not profile:
        profile = UserProfile(user_id=user.id)

    if request.method == 'POST':
        profile.name = request.form.get('name', '').strip()
        profile.location = request.form.get('location', '').strip()
        profile.availability = ','.join(request.form.getlist('availability'))
        profile.is_public = 'is_public' in request.form

        # Save profile photo
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and file.filename:
                filename = secure_filename(f"profile_{user.id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                profile.profile_photo = filename

        db.session.add(profile)

        # Clear old skill
        Skill.query.filter_by(user_id=user.id).delete()

        offered_skill = [s.strip() for s in request.form.get('offered_skill', '').split(',') if s.strip()]
        wanted_skill = [s.strip() for s in request.form.get('wanted_skill', '').split(',') if s.strip()]

        for skill in offered_skill:
            db.session.add(Skill(user_id=user.id, name=skill, type='offered'))
        for skill in wanted_skill:
            db.session.add(Skill(user_id=user.id, name=skill, type='wanted'))

        db.session.commit()

        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))

    # Load skill to prefill form
    skill = Skill.query.filter_by(user_id=user.id).all()
    offered = [s.name for s in skill if s.type == 'offered']
    wanted = [s.name for s in skill if s.type == 'wanted']

    skill = Skill.query.filter_by(user_id=user.id).all()
    
    return render_template('edit_profile.html', user=user, profile=profile,
                       skill=skill,
                       offered_skill=','.join(offered),
                       wanted_skill=','.join(wanted))

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    """View another user's profile"""
    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('profile'))  # fallback if browse not defined

    profile = UserProfile.query.filter_by(user_id=user.id).first()

    # Check if profile is private
    if not profile or (not profile.is_public and session.get('user_id') != user.id):
        flash('This profile is private.', 'warning')
        return redirect(url_for('profile'))  # or 'browse' if you create it

    skill = Skill.query.filter_by(user_id=user.id).all()
    offered_skill = [s.name for s in skill if s.type == 'offered']
    wanted_skill = [s.name for s in skill if s.type == 'wanted']

    # Ratings system placeholder
    ratings = []  # Replace with Rating.query.filter_by(user_id=user.id).all() later
    avg_rating = 0
    if ratings:
        avg_rating = sum(r.rating for r in ratings) / len(ratings)

    # Determine if current user can send a swap request
    can_request = False
    if 'user_id' in session and session['user_id'] != user.id:
        # Example placeholder for checking if request already exists
        can_request = True  # Replace with logic when swap table is created

    return render_template(
        'user_profile.html',
        user=user,
        profile=profile,
        offered_skill=offered_skill,
        wanted_skill=wanted_skill,
        ratings=ratings,
        avg_rating=avg_rating,
        can_request=can_request
    )
@app.route('/send_swap_request', methods=['POST'])
@login_required
def send_swap_request():
    provider_id = int(request.form['provider_id'])
    offered_skill = request.form['offered_skill'].strip()
    wanted_skill = request.form['wanted_skill'].strip()
    message = request.form.get('message', '').strip()

    if not offered_skill or not wanted_skill:
        flash('Please specify both offered and wanted skill.', 'danger')
        return redirect(url_for('user_profile', user_id=provider_id))

    # Check for existing pending request
    existing_request = SwapRequest.query.filter_by(
        requester_id=session['user_id'],
        provider_id=provider_id,
        status='pending'
    ).first()

    if existing_request:
        flash('You already have a pending request with this user.', 'warning')
        return redirect(url_for('user_profile', user_id=provider_id))

    # Create new request
    new_request = SwapRequest(
        requester_id=session['user_id'],
        provider_id=provider_id,
        offered_skill=offered_skill,
        wanted_skill=wanted_skill,
        message=message,
        status='pending'
    )

    db.session.add(new_request)
    db.session.commit()

    flash('Swap request sent successfully!', 'success')
    return redirect(url_for('user_profile', user_id=provider_id))



@app.route('/swap_requests')
@login_required
def swap_requests():
    """View all swap requests (sent and received)"""
    user_id = session['user_id']

    # Get sent requests (where current user is the requester)
    sent_requests = SwapRequest.query.filter_by(requester_id=user_id).all()

    # Get received requests (where current user is the provider)
    received_requests = SwapRequest.query.filter_by(provider_id=user_id).all()

    return render_template('swap_requests.html',
                           sent_requests=sent_requests,
                           received_requests=received_requests)

@app.route('/respond_swap_request', methods=['POST'])
@login_required
def respond_swap_request():
    """Accept or reject a swap request"""
    swap_id = int(request.form['swap_id'])
    action = request.form['action']  # 'accept' or 'reject'

    # Fetch the swap request from DB
    swap = SwapRequest.query.get(swap_id)

    # Validate the request
    if not swap or swap.provider_id != session['user_id']:
        flash('Invalid swap request.', 'danger')
        return redirect(url_for('swap_requests'))

    # Update the status
    if action == 'accept':
        swap.status = 'accepted'
        swap.responded_at = datetime.now()
        flash('Swap request accepted!', 'success')
    elif action == 'reject':
        swap.status = 'rejected'
        swap.responded_at = datetime.now()
        flash('Swap request rejected.', 'info')
    else:
        flash('Invalid action.', 'danger')
        return redirect(url_for('swap_requests'))

    db.session.commit()
    return redirect(url_for('swap_requests'))

@app.route('/cancel_swap_request/<int:swap_id>')
@login_required
def cancel_swap_request(swap_id):
    """Cancel a sent swap request"""
    swap = SwapRequest.query.get(swap_id)

    if not swap or swap.requester_id != session['user_id']:
        flash('Invalid swap request.', 'danger')
        return redirect(url_for('swap_requests'))

    if swap.status != 'pending':
        flash('Cannot cancel this request.', 'warning')
        return redirect(url_for('swap_requests'))

    db.session.delete(swap)
    db.session.commit()

    flash('Swap request cancelled.', 'info')
    return redirect(url_for('swap_requests'))
from datetime import datetime

@app.route('/complete_swap/<int:swap_id>')
@login_required
def complete_swap(swap_id):
    """Mark a swap as completed"""
    swap = SwapRequest.query.get(swap_id)

    # Validate swap exists and user is involved
    if not swap or (swap.requester_id != session['user_id'] and swap.provider_id != session['user_id']):
        flash('Invalid swap request.', 'danger')
        return redirect(url_for('swap_requests'))

    if swap.status != 'accepted':
        flash('Swap must be accepted before completion.', 'warning')
        return redirect(url_for('swap_requests'))

    swap.status = 'completed'
    swap.completed_at = datetime.now()

    db.session.commit()

    flash('Swap marked as completed! You can now leave a rating.', 'success')
    return redirect(url_for('swap_requests'))

@app.route('/rate_user', methods=['POST'])
@login_required
def rate_user():
    """Rate a user after a completed swap"""
    swap_id = int(request.form['swap_id'])
    rating_value = int(request.form['rating'])
    feedback = request.form.get('feedback', '').strip()

    swap = SwapRequest.query.get(swap_id)

    if not swap or swap.status != 'completed':
        flash('Invalid swap or swap not completed.', 'danger')
        return redirect(url_for('swap_requests'))

    # Identify who is being rated
    if swap.requester_id == session['user_id']:
        rated_user_id = swap.provider_id
    elif swap.provider_id == session['user_id']:
        rated_user_id = swap.requester_id
    else:
        flash('You are not part of this swap.', 'danger')
        return redirect(url_for('swap_requests'))

    # Check for existing rating
    existing_rating = Rating.query.filter_by(
        rater_id=session['user_id'],
        swap_id=swap_id
    ).first()

    if existing_rating:
        flash('You have already rated this swap.', 'warning')
        return redirect(url_for('swap_requests'))

    # Save new rating
    new_rating = Rating(
        rater_id=session['user_id'],
        rated_user_id=rated_user_id,
        swap_id=swap_id,
        rating=rating_value,
        feedback=feedback
    )

    db.session.add(new_rating)
    db.session.commit()

    flash('Rating submitted successfully!', 'success')
    return redirect(url_for('swap_requests'))

from sqlalchemy import func, desc

@app.route('/admin')
@admin_required
def admin():
    """Admin dashboard"""
    
    # Stats
    total_users = db.session.query(func.count(User.id)).scalar()
    total_swaps = db.session.query(func.count(SwapRequest.id)).scalar()
    pending_swaps = db.session.query(func.count(SwapRequest.id)).filter_by(status='pending').scalar()
    completed_swaps = db.session.query(func.count(SwapRequest.id)).filter_by(status='completed').scalar()
    total_ratings = db.session.query(func.count(Rating.id)).scalar()

    stats = {
        'total_users': total_users,
        'total_swaps': total_swaps,
        'pending_swaps': pending_swaps,
        'completed_swaps': completed_swaps,
        'total_ratings': total_ratings
    }

    # Recent 10 users (sorted by created_at, descending)
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()

    # Recent 10 swaps with requester and provider info
    recent_swaps = (
        SwapRequest.query
        .order_by(SwapRequest.created_at.desc())
        .limit(10)
        .all()
    )

    return render_template('admin.html', stats=stats,
                           recent_users=recent_users,
                           recent_swaps=recent_swaps)
@app.route('/admin/ban_user/<int:user_id>')
@admin_required
def ban_user(user_id):
    """Ban a user"""
    user = User.query.get(user_id)

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin'))

    if user.is_admin:
        flash('Cannot ban admin users.', 'warning')
        return redirect(url_for('admin'))

    user.is_banned = True
    db.session.commit()

    flash(f'User {user.username} has been banned.', 'success')
    return redirect(url_for('admin'))
@app.route('/admin/unban_user/<int:user_id>')
@admin_required
def unban_user(user_id):
    """Unban a user"""
    user = User.query.get(user_id)

    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin'))

    user.is_banned = False
    db.session.commit()

    flash(f'User {user.username} has been unbanned.', 'success')
    return redirect(url_for('admin'))
@app.route('/admin/delete_swap/<int:swap_id>')
@admin_required
def delete_swap(swap_id):
    """Delete a swap request"""
    swap = SwapRequest.query.get(swap_id)

    if not swap:
        flash('Swap request not found.', 'danger')
        return redirect(url_for('admin'))

    db.session.delete(swap)
    db.session.commit()

    flash('Swap request deleted.', 'success')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    # Create admin user if it doesn't exist
    from werkzeug.security import generate_password_hash

    with app.app_context():
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@skillwap.com',
                password_hash=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("✅ Admin user created: admin / admin123")

    app.run(host='0.0.0.0', port=5000, debug=True)

