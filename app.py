from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import mysql.connector
import os
import re
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = "0000000000"  # secure random secret

# Email Configuration
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "oldbookstorenepal@gmail.com"  
app.config["MAIL_PASSWORD"] = "terd wtfd uazx aksq"  
app.config["MAIL_DEFAULT_SENDER"] = "your_email@gmail.com"

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

#File Upload Setup
UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

#Database Configuration
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "",
    "database": "bookstore",
}


def get_db_connection():
    return mysql.connector.connect(**db_config)


# Authentication Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Admins only can access this page.", "danger")
            return redirect(url_for("home"))
        return f(*args, **kwargs)

    return decorated_function

# Home Page
@app.route("/")
def home():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute( """  SELECT b.bookID, b.book_name, b.author, b.price, b.selling_price, b.`condition`, b.image_path, c.category_name FROM book b 
                   JOIN category c ON b.categoryID = c.categoryID  WHERE b.status = 'Available' ORDER BY b.posted_date DESC  LIMIT 20 """ )
    books = cursor.fetchall()
    cursor.close()
    conn.close()

    team_members = [
        {"name": "Birendra Chaudhary", "image": "team/Biru.png"},
        {"name": "Dilli Raj Bhatta", "image": "team/dilli.jpg"},
        {"name": "Kaustubh Pant", "image": "team/member.png"},
        {"name": "Santosh Rana", "image": "team/santosh.jpg"},
    ]

    return render_template("index.html", books=books, team_members=team_members)

#Authentication Routes
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""SELECT u.*, r.rolename FROM user u JOIN role r ON u.roleID = r.roleID WHERE u.email = %s""",(email,),)
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user["password"], password):
            if not user["is_verified"]:
                flash(f"Your account is not verified. Click below to resend the verification email for {email}.","warning",)
                session["unverified_email"] = email  # store temporarily
                return redirect(url_for("login"))
            
            session["user_id"] = user["userID"]
            session["username"] = user["username"]
            session["role"] = user["rolename"]
            flash("Login successful!", "success")

            if user["rolename"] == "admin":
                return redirect(url_for("admin"))
            else:
                return redirect(url_for("home"))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form["full_name"].strip()
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        phoneno = request.form["phoneno"]
        address = request.form["address"]
        password = request.form["password"].strip()

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return redirect(url_for("register"))

        if not re.search(r"\d", password):
            flash("Password must contain at least one number.", "danger")
            return redirect(url_for("register"))

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            flash("Password must contain at least one special character.", "danger")
            return redirect(url_for("register"))
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT roleID FROM `role` WHERE rolename = 'user'")
        role = cursor.fetchone()

        if not role:
            flash("User role not found in the database.", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for("register"))

        role_id = role[0]

        # Check if email already exists
        cursor.execute("SELECT * FROM `user` WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            flash("Email is already registered. Please log in.", "warning")
            cursor.close()
            conn.close()
            return redirect(url_for("login"))

        try:
            # Insert new user (not verified yet)
            cursor.execute("""INSERT INTO `user` (full_name, username, email, phoneno, address, password, roleID, is_verified) VALUES (%s, %s, %s, %s, %s, %s, %s, 0)""",(full_name, username, email, phoneno, address, hashed_password, role_id,),)
            conn.commit()

            # Generate token for email verification
            token = s.dumps(email, salt="email-confirm-salt")
            confirm_url = url_for("confirm_email", token=token, _external=True)

            # Send verification email
            msg = Message("Confirm Your Email - Old Book Store", recipients=[email])
            msg.body = f"""
Hi {username},
Welcome to Old Book Store! Please confirm your email address by clicking the link below:

{confirm_url}

This link will expire in 1 hour. If you did not register, please ignore this email."""
            mail.send(msg)

            flash("Registration successful! Please check your email to verify your account.","info",)
            return redirect(url_for("login"))

        except mysql.connector.Error as err:
            flash(f"Error during registration: {err}", "danger")

        finally:
            cursor.close()
            conn.close()

    return render_template("login.html")

# Email Verification
@app.route("/confirm_email/<token>")
def confirm_email(token):
    try:
        # Decode token and get email which is expire in 1 hour 
        email = s.loads(
            token, salt="email-confirm-salt", max_age=3600
        )  
    except SignatureExpired:
        flash("The confirmation link has expired. Login to get another link ", "danger")
        return redirect(url_for("register"))
    except BadSignature:
        flash("Invalid confirmation link.", "danger")
        return redirect(url_for("register"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM user WHERE email = %s", (email,))
    user = cursor.fetchone()

    if user:
        cursor.execute("UPDATE user SET is_verified = 1 WHERE email = %s", (email,))
        conn.commit()
        flash("Your email has been verified successfully! You can now log in.", "success")
    else:
        flash("User not found.", "danger")

    cursor.close()
    conn.close()
    return redirect(url_for("login"))

# Resend Verification code to verify
@app.route("/resend_verification", methods=["POST"])
def resend_verification():
    email = request.form.get("email")

    if not email:
        flash("Please enter your email to resend verification.", "warning")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM user WHERE email = %s", (email,))
    user = cursor.fetchone()

    if not user:
        flash("Email not found. Please register first.", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for("register"))

    if user["is_verified"]:
        flash("This email is already verified. Please log in.", "info")
        cursor.close()
        conn.close()
        return redirect(url_for("login"))

    # Generate a new token
    token = s.dumps(email, salt="email-confirm-salt")
    confirm_url = url_for("confirm_email", token=token, _external=True)

    # Send verification email again
    msg = Message("Resend: Confirm Your Email - Old Book Store", recipients=[email])
    msg.body = f"""
Hi {user['username']},

Here’s your new email verification link:

{confirm_url}

This link will expire in 1 hour. If you did not request this, ignore it.
"""
    mail.send(msg)

    flash("A new verification email has been sent. Please check your inbox.", "info")
    cursor.close()
    conn.close()
    return redirect(url_for("login"))

# Forgot Pasword
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        # Check if user exists in DB
        db = mysql.connector.connect(
            host="localhost", user="root", password="", database="bookstore"
        )
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM user WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        db.close()

        if user:
            token = s.dumps(email, salt="password-reset-salt")
            reset_url = url_for("reset_password", token=token, _external=True)

            # Send email
            msg = Message("Password Reset Request", recipients=[email])
            msg.body = f"""
Hi {user['username']},

You requested a password reset for your Old Book Store account.
Click the link below to reset your password:

{reset_url}

This link will expire in 1 hour. If you didn’t request this, please ignore this email.
"""
            mail.send(msg)
            flash("A password reset link has been sent to your email address.", "success")
        else:
            flash("No account found with that email address.", "error")

        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = s.loads(token, salt="password-reset-salt", max_age=3600)  # 1 hour expiry
    except SignatureExpired:
        flash("The reset link has expired.", "error")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("Invalid reset token.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form["password"]
        hashed_password = generate_password_hash(new_password)

        db = mysql.connector.connect(host="localhost", user="root", password="", database="bookstore")
        cursor = db.cursor()
        cursor.execute("UPDATE user SET password = %s WHERE email = %s", (hashed_password, email) )
        db.commit()
        cursor.close()
        db.close()

        flash("Your password has been reset successfully. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")

#sell 
@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        book_name = request.form["book_name"].strip()
        author = request.form["author"].strip()
        edition = request.form.get("edition", "").strip()
        description = request.form.get("description", "").strip()
        condition = request.form["condition"]
        category_name = request.form["category"].strip()

        try:
            original_price = float(request.form["original_price"])
            selling_price = float(request.form["selling_price"])
        except ValueError:
            flash("Invalid price input.", "danger")
            return redirect(url_for("sell"))

        image = request.files.get("book_image")
        if not image or image.filename == "":
            flash("Please upload an image of the book.", "danger")
            return redirect(url_for("sell"))

        filename = secure_filename(image.filename)
        image_path = os.path.join(UPLOAD_FOLDER, filename)
        image.save(image_path)

        relative_path = os.path.join("uploads", filename).replace("\\", "/")

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT categoryID FROM category WHERE category_name = %s", (category_name,))
        category = cursor.fetchone()
        if not category:
            cursor.execute("INSERT INTO category (category_name) VALUES (%s)", (category_name,) )
            conn.commit()
            category_id = cursor.lastrowid
        else:
            category_id = category[0]

        cursor.execute("""INSERT INTO book (book_name, author, edition, description, `condition`, price, selling_price, image_path, posted_date, userID, categoryID, status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s, %s, 'Available')""",
        (book_name, author, edition, description, condition, original_price, selling_price, relative_path, session.get("user_id"), category_id,),)
        conn.commit()
        cursor.close()
        conn.close()

        flash("Book listed successfully!", "success")
        return redirect(url_for("sell"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT categoryID, category_name FROM category")
    categories = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("sellbook.html", categories=categories)

# Buy 
@app.route("/buy")
@login_required
def buy():
    search = request.args.get("search", "").strip()
    conn = get_db_connection()
    cursor = conn.cursor()

    if search:
        cursor.execute("""SELECT b.bookID, c.category_name, b.book_name, b.author, b.edition, b.`condition`, b.price, b.selling_price, b.image_path, b.status FROM book b JOIN category c ON b.categoryID = c.categoryID WHERE b.book_name LIKE %s OR b.author LIKE %s
            ORDER BY b.posted_date DESC""",(f"%{search}%", f"%{search}%"),)
    else:
        cursor.execute(""" SELECT b.bookID, c.category_name, b.book_name, b.author, b.edition, b.`condition`, b.price, b.selling_price, b.image_path, b.status FROM book b JOIN category c ON b.categoryID = c.categoryID ORDER BY b.posted_date DESC""")

    results = cursor.fetchall()
    cursor.close()
    conn.close()

    books_by_category = {}
    for book in results:
        category = book[1]
        books_by_category.setdefault(category, []).append(book)

    return render_template("buy.html", books_by_category=books_by_category)

# Route detailed information about a single book
@app.route("/book/<int:book_id>")
def book_detail(book_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""SELECT b.bookID, b.book_name, b.author, b.edition, b.description, b.`condition`, b.price, b.selling_price, b.image_path, b.posted_date, c.category_name, u.username, b.userID
        FROM book b JOIN category c ON b.categoryID = c.categoryID JOIN `user` u ON b.userID = u.userID WHERE b.bookID = %s""", (book_id,),)
    book = cursor.fetchone()
    cursor.close()
    conn.close()

    if not book:
        flash("Book not found.", "warning")
        return redirect(url_for("home"))

    if isinstance(book["posted_date"], str):
        try:
            book["posted_date"] = datetime.strptime(book["posted_date"], "%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

    return render_template("bookdetail.html", book=book)

# Route that help to add book in wishlist
@app.route("/add_to_wishlist/<int:book_id>", methods=["POST"])
@login_required
def add_to_wishlist(book_id):
    user_id = session.get("user_id")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Prevent user adding own book to wishlist
    cursor.execute("SELECT userID FROM book WHERE bookID = %s", (book_id,))
    book_owner = cursor.fetchone()
    if not book_owner:
        flash("Book not found.", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for("buy"))
    if book_owner[0] == user_id:
        flash("You cannot add your own uploaded book to wishlist.", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for("book_detail", book_id=book_id))

    cursor.execute("SELECT wishlistid FROM wishlist WHERE userid = %s AND bookid = %s", (user_id, book_id),)
    exists = cursor.fetchone()

    if not exists:
        cursor.execute("INSERT INTO wishlist (userid, bookid, added_date) VALUES (%s, %s, NOW())",(user_id, book_id),)
        conn.commit()

    cursor.close()
    conn.close()
    return redirect(url_for("buy"))


@app.route("/wishlist")
@login_required
def wishlist():
    user_id = session.get("user_id")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""SELECT w.wishlistid, b.bookID, b.book_name, b.selling_price, b.image_path FROM wishlist w JOIN book b ON w.bookid = b.bookID WHERE w.userid = %s """, (user_id,), )
    wishlist_items = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template("wishlist.html", wishlist_items=wishlist_items)


@app.route("/remove_from_wishlist/<int:wishlistid>", methods=["POST"])
@login_required
def remove_from_wishlist(wishlistid):
    user_id = session.get("user_id")
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM wishlist WHERE wishlistid = %s AND userid = %s", (wishlistid, user_id), )
        conn.commit()
        flash("Item removed from wishlist.", "info")
    except mysql.connector.Error as err:
        flash(f"Error removing item from wishlist: {err}", "danger")
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for("wishlist"))


@app.route("/order_from_wishlist", methods=["POST"])
@login_required
def order_from_wishlist():
    selected_books = request.form.getlist("selected_books")
    user_id = session.get("user_id")

    if not selected_books:
        flash("No books selected to order.", "warning")
        return redirect(url_for("wishlist"))

    conn = get_db_connection()
    cursor = conn.cursor()

    for book_id_str in selected_books:
        try:
            book_id = int(book_id_str)  
        except ValueError:
            continue

        cursor.execute("SELECT selling_price FROM book WHERE bookID = %s", (book_id,))
        price_result = cursor.fetchone()
        if not price_result:
            continue

        total_amount = float(price_result[0])

        #Insert into orders
        cursor.execute(""" INSERT INTO orders (userID, bookID, order_date, status, total_amount) VALUES (%s, %s, NOW(), %s, %s) """, (user_id, book_id, "Pending", total_amount), )
        order_id = cursor.lastrowid

        #Insert into payment and checkout
        cursor.execute(""" INSERT INTO payment (orderid, payment_method, amount, transaction_status, payment_date)  VALUES (%s, %s, %s, %s, NOW()) """, (order_id, "Cash on Delivery", total_amount, "Pending"), )

        #Remove from wishlist
        cursor.execute("DELETE FROM wishlist WHERE userid = %s AND bookid = %s", (user_id, book_id) )

    conn.commit()
    cursor.close()
    conn.close()

    flash( "Your order(s) have been placed successfully and removed from wishlist!", "success", )
    return redirect(url_for("orders"))


@app.route("/place_order/<int:book_id>", methods=["POST"])
@login_required
def place_order(book_id):
    user_id = session.get("user_id")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Get book price
    cursor.execute("SELECT selling_price FROM book WHERE bookID = %s", (book_id,))
    book = cursor.fetchone()
    if not book:
        flash("Book not found.", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for("buy"))

    total_amount = float(book["selling_price"])

    # Insert order
    cursor.execute("""INSERT INTO orders (userID, bookID, order_date, status, total_amount) VALUES (%s, %s, NOW(), %s, %s) """, (user_id, book_id, "Pending", total_amount),)
    order_id = cursor.lastrowid

    # Paymnet
    cursor.execute( """ INSERT INTO payment (orderid, payment_method, amount, transaction_status, payment_date) VALUES (%s, %s, %s, %s, NOW())""", (order_id, "Cash on Delivery", total_amount, "Pending"), )

    conn.commit()
    cursor.close()
    conn.close()
    flash("Order placed successfully!", "success")
    return redirect(url_for("orders"))


@app.route("/checkout/<int:book_id>", methods=["GET", "POST"])
@login_required
def checkout(book_id):
    user_id = session.get("user_id")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch book details
    cursor.execute("""SELECT b.bookID, b.book_name, b.author, b.selling_price, b.image_path,  u.username AS seller_name, u.email AS seller_email, b.status, b.userID AS seller_id 
                   FROM book b JOIN `user` u ON b.userID = u.userID WHERE b.bookID = %s """, (book_id,),)
    book = cursor.fetchone()

    if not book:
        flash("Book not found for checkout.", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for("buy"))

    if book["seller_id"] == user_id:
        flash("You cannot buy your own uploaded book.", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for("book_detail", book_id=book_id))

    if book["status"] == "Sold":
        flash("This book is already sold.", "warning")
        cursor.close()
        conn.close()
        return redirect(url_for("buy"))

    # checkout form submitted
    if request.method == "POST":
        fullname = request.form["fullname"]
        phone = request.form["phone"]
        address = request.form["address"]
        payment_method = request.form["payment_method"]

        if not phone.isdigit() or len(phone) != 10:
            flash("Please enter a valid 10-digit phone number.", "danger")
            cursor.close()
            conn.close()
            return redirect(url_for("checkout", book_id=book_id))

        try:
            cursor.execute( """INSERT INTO orders (userID, bookID, order_date, status, total_amount, fullname, phone, address)VALUES (%s, %s, NOW(), %s, %s, %s, %s, %s)""", ( user_id, book_id,  "Pending",  book["selling_price"],  fullname,  phone,  address, ), )
            conn.commit()
            order_id = cursor.lastrowid

            # Insert payment record which is linked to order
            cursor.execute(""" INSERT INTO payment (orderid, payment_method, amount, transaction_status, payment_date) VALUES (%s, %s, %s, %s, NOW())""", (order_id, payment_method, book["selling_price"], "Pending"), )
            conn.commit()

            # Update book as sold
            cursor.execute("UPDATE book SET status = 'Sold' WHERE bookID = %s", (book_id,))
            conn.commit()

            # Remove from wishlist if it exists
            cursor.execute( "DELETE FROM wishlist WHERE userid = %s AND bookid = %s", (user_id, book_id), )
            conn.commit()

            flash("Order placed successfully! Your payment is recorded as pending.", "success",)
            return redirect(url_for("orders"))

        except mysql.connector.Error as err:
            flash(f"Error placing order: {err}", "danger")

        finally:
            cursor.close()
            conn.close()

    cursor.close()
    conn.close()
    return render_template("checkout.html", book=book)


@app.route("/orders")
@login_required
def orders():
    user_id = session.get("user_id")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute( """ SELECT o.orderID as id, o.order_date, o.status, b.bookID, b.book_name, b.author, b.selling_price, b.image_path, p.payment_method, p.transaction_status FROM orders o
        JOIN book b ON o.bookID = b.bookID LEFT JOIN payment p ON o.orderID = p.orderid  WHERE o.userID = %s ORDER BY o.order_date DESC """, (user_id,), )
    orders = cursor.fetchall()
    cursor.close()
    conn.close()

    for order in orders:
        if isinstance(order["order_date"], str):
            try:
                order["order_date"] = datetime.strptime( order["order_date"], "%Y-%m-%d %H:%M:%S" )
            except Exception:
                pass

    return render_template("orders.html", orders=orders)


@app.route("/cancel_order/<int:order_id>", methods=["POST"])
@login_required
def cancel_order(order_id):
    user_id = session.get("user_id")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ✅ Check if order exists and is cancelable
    cursor.execute("SELECT * FROM orders WHERE orderID = %s AND userID = %s AND status = 'Pending'",(order_id, user_id),)
    order = cursor.fetchone()

    if not order:
        flash("Order not found or cannot be canceled.", "danger")
        cursor.close()
        conn.close()
        return redirect(url_for("orders"))

    # ✅ Update order status to Cancelled
    cursor.execute( "UPDATE orders SET status = 'Cancelled' WHERE orderID = %s", (order_id,) )

    # ✅ Update book status back to Available
    cursor.execute("UPDATE book SET status = 'Available' WHERE bookID = %s", (order["bookID"],))

    # ✅ Update corresponding payment status to Failed
    cursor.execute( """  UPDATE payment   SET transaction_status = 'Failed' WHERE orderid = %s """, (order_id,), )

    conn.commit()
    cursor.close()
    conn.close()

    flash("Order cancelled successfully. Payment marked as failed and book is now available.",  "success", )
    return redirect(url_for("orders"))


@app.route("/messages")
@login_required
def messages():
    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Query distinct conversations (user + book) involving current user
    cursor.execute("""SELECT u.userID AS user_id, u.username, b.bookID AS book_id, b.book_name, MAX(m.timestamp) AS last_message_time FROM messages m JOIN `user` u ON u.userID = CASE  WHEN m.sender_id = %s THEN m.receiver_id ELSE m.sender_id
        END JOIN book b ON m.book_id = b.bookID WHERE %s IN (m.sender_id, m.receiver_id) GROUP BY u.userID, u.username, b.bookID, b.book_name ORDER BY last_message_time DESC """,  (user_id, user_id),)
    convos = cursor.fetchall()

    conversations = []
    for c in convos:
        # Fetch last message content
        cursor.execute( """SELECT message, timestamp FROM messages  WHERE ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s)) AND book_id = %s  ORDER BY timestamp DESC LIMIT 1 """, (user_id, c["user_id"], c["user_id"], user_id, c["book_id"]), )
        last_msg_row = cursor.fetchone()

        # Count unread messages sent by the other user
        cursor.execute( """ SELECT COUNT(*) AS unread_count FROM messages WHERE sender_id = %s AND receiver_id = %s AND book_id = %s AND status = 'unread' """, (c["user_id"], user_id, c["book_id"]), )
        unread_row = cursor.fetchone()

        conversations.append(
            {
                "user_id": c["user_id"],
                "username": c["username"],
                "book_id": c["book_id"],
                "book_name": c["book_name"],
                "last_message": last_msg_row["message"] if last_msg_row else "",
                "last_message_time": (
                    last_msg_row["timestamp"] if last_msg_row else None
                ),
                "unread_count": unread_row["unread_count"] if unread_row else 0,
            }
        )

    cursor.close()
    conn.close()
    return render_template("conversations.html", conversations=conversations)


@app.route("/messages/<int:receiver_id>/<int:book_id>", methods=["GET", "POST"])
@login_required
def message_user_book(receiver_id, book_id):
    sender_id = session["user_id"]
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # POST: save message
    if request.method == "POST":
        message = request.form["message"].strip()
        timestamp = datetime.now()
        cursor.execute( "INSERT INTO messages (sender_id, receiver_id, book_id, message, timestamp, status) VALUES (%s, %s, %s, %s, %s, %s)", (sender_id, receiver_id, book_id, message, timestamp, "unread"), )
        db.commit()
        flash("Message sent!", "success")
        return redirect(
            url_for("message_user_book", receiver_id=receiver_id, book_id=book_id)
        )

    # MARK MESSAGES AS READ AND SEEN
    cursor.execute( """ UPDATE messages SET status = 'read', seen = 1 WHERE sender_id = %s AND receiver_id = %s AND book_id = %s AND status = 'unread' """, (receiver_id, sender_id, book_id), )
    db.commit()

    # GET: show conversation
    cursor.execute("SELECT * FROM `user` WHERE userID = %s", (receiver_id,))
    receiver = cursor.fetchone()

    cursor.execute("SELECT * FROM book WHERE bookID = %s", (book_id,))
    book = cursor.fetchone()

    cursor.execute( """ SELECT m.*, u.username AS sender_name, m.seen FROM messages m JOIN `user` u ON m.sender_id = u.userID WHERE (m.sender_id = %s AND m.receiver_id = %s AND m.book_id = %s)  OR (m.sender_id = %s AND m.receiver_id = %s AND m.book_id = %s)
    ORDER BY m.timestamp ASC """, (sender_id, receiver_id, book_id, receiver_id, sender_id, book_id),)

    messages = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template("chat.html", messages=messages, receiver=receiver, book=book)


#direct message to admin
@app.route("/contact", methods=["POST"])
def contact():
    name = request.form["name"].strip()
    email = request.form["email"].strip()
    phone = request.form.get("phone", "").strip()
    message = request.form["message"].strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(""" INSERT INTO contact_messages (name, email, phone, message) VALUES (%s, %s, %s, %s) """,  (name, email, phone, message), )
    conn.commit()
    cursor.close()
    conn.close()

    flash("Message sent successfully!", "success")
    return redirect(url_for("home"))


@app.route("/admin")
@login_required
@admin_required
def admin():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute( "SELECT full_name, username, email, is_verified FROM `user` WHERE userID = %s", (session["user_id"],), )
    admin_info = cursor.fetchone()

    cursor.execute("""  SELECT userID, full_name, username, email, phoneno, address, is_verified FROM user WHERE roleID != (SELECT roleID FROM role WHERE rolename = 'admin')""" )
    
    users = cursor.fetchall()

    # Ensure Python treats is_verified as boolean
    for u in users:
        u["is_verified"] = bool(u["is_verified"])

    cursor.execute( """ SELECT b.bookID, b.book_name, b.author, c.category_name, b.price, b.selling_price, u.username FROM book b  JOIN category c ON b.categoryID = c.categoryID  JOIN `user` u ON b.userID = u.userID""")
    books = cursor.fetchall()

    cursor.execute("SELECT name, email, message, id FROM contact_messages")
    messages = cursor.fetchall()

    cursor.execute( """  SELECT o.orderID, o.order_date, o.status, u.username,o.fullname,o.phone,o.address, b.book_name, b.selling_price FROM orders o JOIN book b ON o.bookID = b.bookID JOIN `user` u ON o.userID = u.userID
                   ORDER BY o.order_date DESC """)
    orders = cursor.fetchall()

    cursor.execute( """ SELECT p.paymentID, p.payment_method, p.amount, p.transaction_status, p.payment_date, o.orderID, u.username, b.book_name FROM payment p JOIN orders o ON p.orderID = o.orderID  JOIN user u ON o.userID = u.userID JOIN book b ON o.bookID = b.bookID ORDER BY p.payment_date DESC """ )
    payment = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template( "admin.html", users=users, books=books, messages=messages, admin_info=admin_info, orders=orders, payment=payment,)

# admin can remove user
@app.route("/delete_user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM `user` WHERE userID = %s", (user_id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("User deleted successfully.", "info")
    return redirect(url_for("admin"))

# admin can remove book
@app.route("/delete_book/<int:book_id>", methods=["POST"])
@login_required
@admin_required
def delete_book(book_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM book WHERE bookID = %s", (book_id,))
        conn.commit()
        if cursor.rowcount == 0:
            flash("No book was deleted. Possibly invalid ID or FK constraint.", "danger" )
        else:
            flash("Book deleted successfully.", "info")
    except Exception as e:
        flash(f"Error deleting book: {str(e)}", "danger")
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for("admin"))

# admin can remove message
@app.route("/delete_message/<int:msg_id>", methods=["POST"])
@login_required
@admin_required
def delete_message(msg_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM contact_messages WHERE id = %s", (msg_id,))
    conn.commit()
    cursor.close()
    conn.close()
    flash("Message deleted successfully.", "info")
    return redirect(url_for("admin"))

# admin can change the status of order
@app.route("/update_order_status/<int:order_id>", methods=["POST"])
@login_required
@admin_required
def update_order_status(order_id):
    new_status = request.form.get("status")

    if new_status not in ["Pending", "Shipped", "Delivered", "Cancelled"]:
        flash("Invalid status selected.", "danger")
        return redirect(url_for("admin"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE orders SET status = %s WHERE orderID = %s", (new_status, order_id))
    conn.commit()
    cursor.close()
    conn.close()

    flash("Order status updated successfully.", "success")
    return redirect(url_for("admin"))

## admin can update payment
@app.route("/update_payment/<int:payment_id>", methods=["POST"])
@login_required
@admin_required
def update_payment(payment_id):
    new_status = request.form["transaction_status"]

    conn = get_db_connection()
    cursor = conn.cursor()


    cursor.execute("UPDATE payment SET transaction_status = %s WHERE paymentid = %s", (new_status, payment_id),  )

    if new_status == "Completed":
        cursor.execute( """ UPDATE orders  SET status = 'Completed'  WHERE orderid = (SELECT orderid FROM payment WHERE paymentid = %s)""", (payment_id,), )
    else:
        cursor.execute( """ UPDATE orders  SET status = %s  WHERE orderid = (SELECT orderid FROM payment WHERE paymentid = %s) """,(  new_status, payment_id, ), )

    conn.commit()
    cursor.close()
    conn.close()

    flash(f"Payment status updated to {new_status}", "success")
    return redirect(url_for("admin"))


if __name__ == "__main__":
    app.run(debug=True)
