from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import random
import string
import os

app = Flask(__name__)
app.secret_key = 'srujanadeviiahdhbtxfvskzkhg'  # Our secure key

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bookstore.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Email Configuration for OTP
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'd.srujana2024@gmail.com'
app.config['MAIL_PASSWORD'] = 'qeul pckw vxop amhs '
mail = Mail(app)

# ------------------#
# Database Models   #
# ------------------#
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)  # Use hashed passwords in production
    otp = db.Column(db.String(6))
    is_verified = db.Column(db.Boolean, default=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.String(500))
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, default=0)

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    product_id = db.Column(db.Integer, nullable=False)
    quantity = db.Column(db.Integer, default=1)

# ------------------#
# Routes            #
# ------------------#
@app.route('/')
def index():
    return redirect(url_for('login'))  # Redirect to login page immediately

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        # TODO: Implement password hashing here
        new_user = User(email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please login.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            session['user_id'] = user.id
            # Generate OTP
            otp = ''.join(random.choices(string.digits, k=6))
            user.otp = otp
            db.session.commit()
            # Send OTP via email
            try:
                msg = Message("Your OTP Code", sender=app.config['MAIL_USERNAME'], recipients=[user.email])
                msg.body = f"Your OTP code is: {otp}"
                mail.send(msg)
                flash("OTP sent to your email. Please verify.", "info")
            except Exception as e:
                flash("Failed to send OTP email.", "danger")
                print("Error sending OTP:", e)
            return redirect(url_for('verify_otp'))
        else:
            flash("Invalid credentials.", "danger")
    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        otp_entered = request.form['otp']
        if user.otp == otp_entered:
            user.is_verified = True
            user.otp = None  # Clear OTP after verification
            db.session.commit()
            flash("OTP verified. Login successful!", "success")
            return redirect(url_for('index'))
        else:
            flash("Invalid OTP. Try again.", "danger")
    return render_template('verify_otp.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully.", "info")
    return render_template('logout.html')

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        flash("Please login to add items to cart.", "warning")
        return redirect(url_for('login'))
    quantity = int(request.form.get('quantity', 1))
    cart_item = Cart(user_id=session['user_id'], product_id=product_id, quantity=quantity)
    db.session.add(cart_item)
    db.session.commit()
    flash("Product added to cart.", "success")
    return redirect(url_for('index'))

@app.route('/cart')
def cart():
    if 'user_id' not in session:
        flash("Please login to view your cart.", "warning")
        return redirect(url_for('login'))
    user_id = session['user_id']
    # Joining Cart with Product details
    cart_items = db.session.query(Cart, Product).join(Product, Cart.product_id == Product.id).filter(Cart.user_id == user_id).all()
    return render_template('cart.html', cart_items=cart_items)

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session:
        flash("Please login to checkout.", "warning")
        return redirect(url_for('login'))
    if request.method == 'POST':
        # TODO: Integrate actual PayPal payment processing here.
        flash("Payment processed successfully (simulation).", "success")
        # Clear user's cart after checkout
        Cart.query.filter_by(user_id=session['user_id']).delete()
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('checkout.html')

if __name__ == '__main__':
    with app.app_context():
        # If the database doesn't exist, create it and add sample books
        if not os.path.exists('bookstore.db'):
            db.create_all()
            # Add unique computer science books to the database
            sample_books = [
                Product(
                    title="Introduction to Algorithms",
                    description="A comprehensive textbook on algorithms covering a wide range of topics in computer science.",
                    price=59.99,
                    stock=10
                ),
                Product(
                    title="Clean Code: A Handbook of Agile Software Craftsmanship",
                    description="A guide to writing clean and maintainable code by Robert C. Martin.",
                    price=29.99,
                    stock=15
                ),
                Product(
                    title="The Pragmatic Programmer",
                    description="Offers practical advice on software development and coding practices.",
                    price=25.50,
                    stock=12
                ),
                Product(
                    title="Design Patterns: Elements of Reusable Object-Oriented Software",
                    description="A classic work describing common design patterns in software engineering.",
                    price=35.00,
                    stock=8
                ),
                Product(
                    title="Structure and Interpretation of Computer Programs",
                    description="An influential book on computer science principles and programming paradigms.",
                    price=40.99,
                    stock=5
                ),
                Product(
                    title="Artificial Intelligence: A Modern Approach",
                    description="A comprehensive resource on artificial intelligence, covering modern techniques and theories.",
                    price=45.00,
                    stock=7
                ),
                Product(
                    title="Code Complete",
                    description="A practical handbook of software construction that covers coding best practices.",
                    price=38.50,
                    stock=9
                ),
                Product(
                    title="Refactoring: Improving the Design of Existing Code",
                    description="A guide to refactoring techniques and best practices for maintaining and improving code quality.",
                    price=32.00,
                    stock=11
                ),
                Product(
                    title="The Mythical Man-Month",
                    description="A classic on software project management and the challenges of large-scale software engineering.",
                    price=27.99,
                    stock=6
                )
            ]
            for book in sample_books:
                db.session.add(book)
            db.session.commit()
    # Add the port number (5000+)
    app.run(debug=True, port=5000)
