import os
import re

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Query database by userid to get username and cash
    userid = session["user_id"]
    rows = db.execute("SELECT username, cash FROM users WHERE id = :id",
                          id=userid)
    username = rows[0]["username"]
    cashbal = rows[0]["cash"]

    # Query database to get all bought stocks and shares
    rows = db.execute("SELECT symbol, SUM(share) FROM transition WHERE user_id = :id GROUP BY symbol",
                          id=userid)

    stocksum = []
    grandtotal = cashbal
    for i in range(len(rows)):
        row = {}
        row["stock"] = rows[i]["symbol"]
        row["shares"] = rows[i]["SUM(share)"]
        # lookup stock current price
        quote = lookup(row["stock"])
        row["price"] = quote["price"]
        row["name"] = quote["name"]
        row["tvalue"] = row["shares"]*row["price"]
        stocksum.append(row)

        # calculate total
        grandtotal += row["tvalue"]

    return render_template("index.html", username = username, stocksum = stocksum, cashbal = cashbal, total = grandtotal)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure stock symbol was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol", 403)

        # Ensure shares was submitted
        elif not request.form.get("shares"):
            return apology("must provide shares", 403)

        elif int(request.form.get("shares")) < 1:
            return apology("must provide valid shares", 403)

        # Ensure symbol exists
        quote = lookup(request.form.get("symbol"))

        if not quote:
            return apology("must provide valid symbol", 403)
        else:
            singleprice = quote["price"]
            share = int(request.form.get("shares"))
            totalprice = singleprice * share

            # read user's cash
            # Query database for user id
            userid = session["user_id"]
            rows = db.execute("SELECT cash FROM users WHERE id = :id",
                          id=userid)
            cash = rows[0]["cash"]

            if totalprice > cash:
                return apology("transition is not completed", 403)
            else:
                rest = float("{0:.2f}".format(cash - totalprice))
                symbol = request.form.get("symbol")
                time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

                # Query database for table purcash
                rows = db.execute("INSERT INTO transition (user_id, transit_type, symbol, share, price, time) VALUES(:userid, :type, :symbol, :share, :price, :time)",
                                    userid = userid, type = "bought", symbol = symbol, share = share, price = singleprice, time = time)
                # Query database to update user's cash
                rows = db.execute("UPDATE users SET cash=:cash WHERE id=:id", cash = rest, id = userid)


        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # get user id
    userid = session["user_id"]

    # Query database for table transition
    rows = db.execute("SELECT * FROM transition WHERE user_id = :id", id = userid)
    print(rows)
    return render_template("history.html", sum = rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must provide stock's symbol", 403)

        quotes = lookup(request.form.get("symbol"))

        return render_template("quoted.html", symbol=request.form.get("symbol"), quotes=quotes)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
     # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        elif not request.form.get("confirmation"):
            return apology("must provide confirm password", 403)

        elif not request.form.get("confirmation") == request.form.get("password"):
            return apology("must provide same two passwords", 403)

        password = request.form.get("password")
        if len(password) < 8:
            return render_template("register.html", msg = "password must have at least 8 characters")
        elif re.search('[0-9]',password) is None:
            return render_template("register.html", msg = "password must have numbers")
        elif re.search('[A-Z]',password) is None:
            return render_template("register.html", msg = "password must have capital letters")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        if len(rows) > 0:
            return apology("username has existed", 403)

        hash = generate_password_hash(request.form.get("password"))

        # Query database for inserting data
        rows = db.execute("INSERT INTO users(username, hash, cash) VALUES(:username, :hash, '1000')",
                          username=request.form.get("username"), hash=hash)

        # Redirect user to login page
        return redirect("/login")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # get user id
    userid = session["user_id"]

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        share = int(request.form.get("shares"))
        # Ensure username was submitted
        if not symbol:
            return apology("must provide symbol", 403)

        # Ensure user owns this stock
        rows = db.execute("SELECT SUM(share) FROM transition WHERE symbol = :symbol GROUP BY symbol",
                          symbol=symbol)

        if len(rows) == 0:
            return apology("user dose not own this symbol", 403)

        if share < 1:
            return apology("Please enter valid share number", 403)

        if rows[0]["SUM(share)"] < share:
            return apology("Do not have enough shares", 403)

        # Query database to get cash balance
        rows = db.execute("SELECT cash FROM users WHERE id = :id", id=userid)
        cashbal = rows[0]["cash"]

        # get stock current price
        quote = lookup(symbol)
        price = quote["price"]
        cash = cashbal + price * share
        # Query database to update user's cash
        rows = db.execute("UPDATE users SET cash=:cash WHERE id=:id", cash = cash, id = userid)

        # Query database for table purcash
        time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        rows = db.execute("INSERT INTO transition (user_id, transit_type, symbol, share, price, time) VALUES(:userid, :type, :symbol, :share, :price, :time)",
                        userid = userid, type = "sold", symbol = symbol, share = -share, price = price, time = time)

        # Redirect user to home page
        return redirect("/")
    else:
        # Query database to get all bought stocks and shares
        rows = db.execute("SELECT symbol FROM transition WHERE user_id = :id GROUP BY symbol",
                              id=userid)
        stocks = []
        for i in range(len(rows)):
            stocks.append(rows[i]["symbol"])

        return render_template("sell.html", stocks = stocks)

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    """Allow users to change their password and add additional cash to their accounts"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
         # Ensure current password was submitted
        if not request.form.get("cpassword"):
            return apology("must provide current password", 403)

        # Ensure new password was submitted
        elif not request.form.get("npassword"):
            return apology("must provide new password", 403)

        # Ensure confirmed new password was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide confirmed new password", 403)

        # Ensure new password and confirmed password are match
        elif not request.form.get("confirmation") == request.form.get("npassword"):
            return apology("must provide same two passwords", 403)

        password = request.form.get("npassword")
        if len(password) < 8:
            return render_template("settings.html", msg = "password must have at least 8 characters")
        elif re.search('[0-9]',password) is None:
            return render_template("settings.html", msg = "password must have numbers")
        elif re.search('[A-Z]',password) is None:
            return render_template("settings.html", msg = "password must have capital letters")

        # get user id
        userid = session["user_id"]

        # Query database for user password
        rows = db.execute("SELECT hash FROM users WHERE id = :userid",
                          userid = userid)

        # Ensure username exists and password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("cpassword")):
            return apology("your password is not right", 403)

        # change user table's password
        hash = generate_password_hash(request.form.get("npassword"))
        rows = db.execute("UPDATE users SET hash = :hash WHERE id = :userid", hash = hash, userid = userid)

        # Redirect user to login page
        return redirect("/login")
    else:
        return render_template("settings.html")

@app.route("/addcash", methods=["POST"])
@login_required
def addcash():
    cash = int(request.form.get("cash"))
     # Ensure cash amount was submitted
    if not cash:
        return apology("must provide cash amount", 403)

    # Ensure cash is positive
    if cash < 1:
        return apology("must provide valid amount", 403)

    # get user id
    userid = session["user_id"]

    # Query database for user password
    rows = db.execute("SELECT cash FROM users WHERE id = :userid",
                          userid = userid)

    totalcash = cash + rows[0]["cash"]
    # Update user's cash
    rows = db.execute("UPDATE users SET cash = :cash WHERE id = :userid", cash = totalcash, userid = userid)

    # Redirect user to home page
    return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
