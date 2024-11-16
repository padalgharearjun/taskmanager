from app import app, db
from app.models import User
from flask import render_template, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash
from flask import session
from datetime import datetime
from flask import Response
import csv


from app.models import Task
from flask import redirect, url_for, request, render_template, flash, session

from functools import wraps
from flask import redirect, url_for, session, flash
from functools import wraps

from flask import make_response

def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "-1"
        return response
    return no_cache



def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        security_question = request.form['security_question']
        security_answer = request.form['security_answer']
        
        # Hash the password
        password_hash = generate_password_hash(password)

        # Create a new user with all required fields
        new_user = User(
            username=username,
            password_hash=password_hash,
            security_question=security_question,
            security_answer=security_answer
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please log in.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {str(e)}')
    
    return render_template('signup.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the user exists
        user = User.query.filter_by(username=username).first()

        if user is None or not user.check_password(password):
            #flash('Invalid username or password')
            flash("Invalid username or password", "danger")
            return redirect(url_for('login'))

        # Log the user in by storing their username in the session
        session['username'] = user.username
        flash(f'Welcome, {user.username}!')
        return redirect(url_for('home'))

    return render_template('login.html')



@app.route('/logout', methods=['POST'])
@login_required
@nocache
def logout():
    session.pop('username', None)
    # Clear the session data, including any flash messages
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('view_tasks'))
    else:
        return redirect(url_for('login'))




@app.route('/create_task', methods=['GET', 'POST'])
@login_required
@nocache
def create_task():
    if 'username' not in session:
        flash('Please log in to create a task.')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        due_date_str = request.form['due_date']
        priority = request.form['priority']

        # Convert the due_date from string to datetime object
        if due_date_str:
            due_date = datetime.strptime(due_date_str, '%Y-%m-%d')
        else:
            due_date = None

        # Get the current user
        user = User.query.filter_by(username=session['username']).first()

        # Create a new task
        new_task = Task(
            title=title,
            description=description,
            due_date=due_date,  # Pass the converted datetime object
            priority=priority,
            user_id=user.id
        )

        # Add the task to the database
        db.session.add(new_task)
        db.session.commit()

        flash('Task created successfully!')
        return redirect(url_for('view_tasks'))

    return render_template('create_task.html')

from datetime import datetime
from flask import request, flash

@app.route('/tasks', methods=['GET', 'POST'])
@login_required
@nocache
def view_tasks():
    if 'username' not in session:
        flash('Please log in to view your tasks.')
        return redirect(url_for('login'))

    # Get the current user
    user = User.query.filter_by(username=session['username']).first()

    # Get all tasks for the current user
    all_tasks = Task.query.filter_by(user_id=user.id).all()

    # Calculate total tasks and priority counts
    total_tasks = len(all_tasks)
    high_priority_tasks = sum(1 for task in all_tasks if task.priority == 'High')
    medium_priority_tasks = sum(1 for task in all_tasks if task.priority == 'Medium')
    low_priority_tasks = sum(1 for task in all_tasks if task.priority == 'Low')

    # Calculate completed and pending counts for each priority
    high_priority_completed = sum(1 for task in all_tasks if task.priority == 'High' and task.completed)
    high_priority_pending = high_priority_tasks - high_priority_completed

    medium_priority_completed = sum(1 for task in all_tasks if task.priority == 'Medium' and task.completed)
    medium_priority_pending = medium_priority_tasks - medium_priority_completed

    low_priority_completed = sum(1 for task in all_tasks if task.priority == 'Low' and task.completed)
    low_priority_pending = low_priority_tasks - low_priority_completed

    # Get search parameters
    search_query = request.args.get('search', '')
    priority_filter = request.args.get('priority', '')
    status_filter = request.args.get('status', '')
    due_date_filter = request.args.get('due_date', '')

    # Start with base query
    tasks_query = Task.query.filter_by(user_id=user.id).order_by(Task.id.desc())

    # Apply search filters
    if search_query:
        tasks_query = tasks_query.filter(
            (Task.title.ilike(f'%{search_query}%')) | (Task.description.ilike(f'%{search_query}%'))
        )

    if priority_filter:
        tasks_query = tasks_query.filter_by(priority=priority_filter)

    if status_filter:
        if status_filter == 'Completed':
            tasks_query = tasks_query.filter_by(completed=True)
        elif status_filter == 'Pending':
            tasks_query = tasks_query.filter_by(completed=False)

    if due_date_filter:
        try:
            # Convert the input string to a datetime object
            due_date = datetime.strptime(due_date_filter, '%Y-%m-%d').date()
            # Filter tasks with due dates on or before the selected date
            tasks_query = tasks_query.filter(Task.due_date <= due_date)
        except ValueError:
            flash('Invalid date format. Please use the date picker to select a date.')

    # Get all tasks without pagination
    tasks = tasks_query.all()

    # Render the template with all the required data
    return render_template(
        'view_tasks.html',
        tasks=tasks,
        search_query=search_query,
        priority_filter=priority_filter,
        status_filter=status_filter,
        due_date_filter=due_date_filter,
        total_tasks=total_tasks,
        high_priority_tasks=high_priority_tasks,
        medium_priority_tasks=medium_priority_tasks,
        low_priority_tasks=low_priority_tasks,
        high_priority_completed=high_priority_completed,
        high_priority_pending=high_priority_pending,
        medium_priority_completed=medium_priority_completed,
        medium_priority_pending=medium_priority_pending,
        low_priority_completed=low_priority_completed,
        low_priority_pending=low_priority_pending
    )



@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
@login_required
@nocache
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)

    if request.method == 'POST':
        task.title = request.form['title']
        task.description = request.form['description']
        
        due_date_str = request.form['due_date']

        # Convert the due_date string to a datetime object if it's not empty
        if due_date_str:
            task.due_date = datetime.strptime(due_date_str, '%Y-%m-%d')
        else:
            task.due_date = None

        task.priority = request.form['priority']
        task.completed = 'completed' in request.form

        # Save the changes to the database
        db.session.commit()
        flash('Task updated successfully!')
        return redirect(url_for('view_tasks'))

    return render_template('edit_task.html', task=task)


@app.route('/delete_task/<int:task_id>')
@login_required
@nocache
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    db.session.delete(task)
    db.session.commit()
    flash('Task deleted successfully!')
    return redirect(url_for('view_tasks'))

from werkzeug.security import generate_password_hash

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        security_question = request.form['security_question']
        security_answer = request.form['security_answer']

        # Find the user by username
        user = User.query.filter_by(username=username).first()

        if user:
            # Verify security question and answer
            if user.security_question == security_question and user.security_answer == security_answer:
                return redirect(url_for('reset_password', user_id=user.id))
            else:
                flash('Incorrect answer to the security question.')
        else:
            flash('No user found with that username.')

    return render_template('forgot_password.html')

@app.route('/reset_password/<int:user_id>', methods=['GET', 'POST'])
def reset_password(user_id):
    user = User.query.get(user_id)

    if not user:
        flash('User not found.')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        flash('Password has been updated successfully!')
        return redirect(url_for('login'))

    return render_template('reset_password.html', user=user)


import csv
from flask import Response, request, session, flash
from datetime import datetime

@app.route('/download_report', methods=['GET'])
@login_required
@nocache
def download_report():
    # Get search parameters from the request
    search_query = request.args.get('search', '')
    priority_filter = request.args.get('priority', '')
    due_date_filter = request.args.get('due_date', '')

    # Get the current user
    user = User.query.filter_by(username=session['username']).first()

    # Start with base query
    tasks_query = Task.query.filter_by(user_id=user.id)

    # Apply filters
    if search_query:
        tasks_query = tasks_query.filter(
            (Task.title.ilike(f'%{search_query}%')) | (Task.description.ilike(f'%{search_query}%'))
        )
    if priority_filter:
        tasks_query = tasks_query.filter_by(priority=priority_filter)
    if due_date_filter:
        try:
            due_date = datetime.strptime(due_date_filter, '%Y-%m-%d').date()
            tasks_query = tasks_query.filter(Task.due_date <= due_date)
        except ValueError:
            flash('Invalid date format.')

    tasks = tasks_query.all()

    # Create CSV response
    def generate_csv():
        output = []
        output.append(['Title', 'Description', 'Due Date', 'Priority', 'Status'])  # CSV header

        for task in tasks:
            output.append([
                task.title,
                task.description,
                task.due_date.strftime('%Y-%m-%d') if task.due_date else 'No due date',
                task.priority,
                'Completed' if task.completed else 'Not Completed'
            ])

        # Create the CSV string
        csv_string = '\n'.join([','.join(row) for row in output])
        return csv_string

    # Set response to CSV format and provide download filename
    response = Response(generate_csv(), mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=tasks_report.csv'

    return response





