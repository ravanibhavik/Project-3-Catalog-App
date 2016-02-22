from flask import Flask, abort, render_template, request, redirect, jsonify, url_for, flash, make_response
app = Flask(__name__)

from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from database_setup import Base, Category, Item, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import json
import httplib2
import requests

# Connect to Database and create database session
engine = create_engine('sqlite:///catalogapp.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(open('templates/client_secrets.json', 'r').read())['web']['client_id']
print(CLIENT_ID)
APPLICATION_NAME = "Catalog Application"


# method to set up new 32-digit state variable and display login page to allow user
# to login using google or facebook account
@app.route("/login")
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# method to connect user to facebook account and create new user in database
# if user connecting facebook account for first time
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('templates/fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('templates/fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&' \
          'client_id=%s&client_secret=%s&fb_exchange_token=%s' % \
          (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print(result)

    # Use token to get user info from API
    # userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]
    print("Token:" + token)

    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print("Facebook User Info:" + result)
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout,
    # let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserId(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


# method to connect user to google account and create new user in database if
# user is logging in using google account for first time
@app.route("/gconnect", methods=['POST'])
def gconnect():
    print("Request Args: " + json.dumps(request.args))
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('templates/client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    print("Access token: " + access_token)
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    print("Result: " + json.dumps(result))
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    gplus_id = credentials.id_token['sub']
    print("gplus id: " + gplus_id)
    if result['user_id'] != gplus_id:
        response = make_response("Token's user id does not match given user id.", 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client id does not match app's", 401))
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    if getUserId(login_session['email']) is None:
        login_session['user_id'] = createUser(login_session)
    else:
        login_session['user_id'] = getUserId(login_session['email'])
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# method to logout user logged in using facebook account
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# method to logout user logged in using account account
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    if 'access_token' not in login_session:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = login_session['access_token']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# method will be called when logged in user clicks Logout and method will call
# gdisconnect or fbdisconnect method as per login_session['provider'] value
@app.route('/disconnect')
def disconnect():
    print(login_session['provider'])
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCategories'))


# JSON APIs to jsonify Items for Single Category
@app.route('/catalog/<int:category_id>/<category_name>/items/JSON')
def categoryItemJSON(category_id, category_name):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


# JSON API to jsonify single Catalog Item
@app.route('/catalog/<int:category_id>/<category_name>/<item_name>/JSON')
def itemJSON(category_id, category_name, item_name):
    item = session.query(Item).filter_by(category_id=category_id, name=item_name).one()
    return jsonify(Item=item.serialize)


# JSON API to jsonify all Categories
@app.route('/catalog/JSON')
def categoryJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


# Display catalog home page
@app.route('/')
@app.route('/catalog/')
def showCategories():
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(Item).order_by(desc(Item.id)).limit(10).all()
    if 'username' not in login_session:
        return render_template('publiccategories.html', categories=categories, items=items)
    else:
        return render_template('categories.html', categories=categories, items=items)


# Show Catalog for selected Category by User on Catalog Home Page
@app.route('/catalog/<int:category_id>/<category_name>/')
def showItems(category_id, category_name):
    try:
        categories = session.query(Category).all()
        category = session.query(Category).filter_by(id=category_id).one()
        items = session.query(Item).filter_by(category_id=category_id).all()
    except NoResultFound:
        return redirect(url_for('showCategories'))
    creator = getUserInfo(category.user_id)
    if 'username' not in login_session:
        return render_template('publicitems.html', categories=categories, items=items, category=category, creator=creator)
    elif category.name != category_name:
        flash('Invalid category name in url')
        return redirect(url_for('showCategories'))
    else:
        return render_template('items.html', categories=categories, items=items, category=category, creator=creator)
     

# Create a new Catalog Item when user clicks 'Add Item' on Catalog page
@app.route('/catalog/new/', methods=['GET', 'POST'])
def newItem():
    try:
        if 'username' not in login_session:
            return redirect(url_for('showLogin'))
    except KeyError:
        return redirect(url_for('showLogin'))
    categories = session.query(Category).all()
    if request.method == 'POST':
        category_id = request.form['category']
        category = session.query(Category).filter_by(id=category_id).one()
        newItem = Item(name=request.form['name'], description=request.form['description'],
                       category_id=category_id, user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New Item %s Successfully Created' % (newItem.name))
        return redirect(url_for('showItems', category_id=category.id, category_name=category.name))
    else:
        return render_template('newitem.html', categories=categories)


# Display Catalog Item name and description when user clicks any Catalog Item on Catalog
# Home Page and allows creator of item to edit and delete Item
@app.route('/catalog/<int:category_id>/<category_name>/<item_name>/')
def displayItem(category_id, category_name, item_name):
    try:
        item = session.query(Item).filter_by(category_id=category_id, name=item_name).first()
    except NoResultFound:
        flash("Invalid url")
        return redirect(url_for('showItems', category_id=category_id, category_name=category_name))
    if 'username' not in login_session:
        return render_template('publicitemdetail.html', item=item)
    elif item.user_id != login_session['user_id']:
        return render_template('itemdetails.html', category_id=category_id, category_name=category_name,
                        item=item, creator='False')
    return render_template('itemdetails.html', category_id=category_id, category_name=category_name,
                           item=item, creator='True')


# Allows creator of Item to edit Item Name, Description and Category and Saves it to database
@app.route('/catalog/<int:category_id>/<category_name>/<item_name>/edit', methods=['GET', 'POST'])
def editItem(category_id, category_name, item_name):
    try:
        if 'username' not in login_session:
            return redirect(url_for('showLogin'))
    except KeyError:
        return redirect(url_for('showLogin'))
    try:
        categories = session.query(Category).all()
        editedItem = session.query(Item).filter_by(category_id=category_id, name=item_name).one()
    except NoResultFound:
        flash("Invalid url")
        return redirect(url_for('showItems', category_id=category_id, category_name=category_name))
    if editedItem.user_id != login_session['user_id']:
        flash("You are not allowed to edit this item.")
        return redirect(url_for('showItems', category_id=category_id, category_name=category_name))
    if request.method == 'POST':
        category_id = request.form['category']
        editedItem.name = request.form['name']
        editedItem.description = request.form['description']
        editedItem.category_id = category_id
        session.commit()
        flash('Item %s Successfully Edited' % (editedItem.name))
        return redirect(url_for('showItems', category_id=category_id, category_name=category_name))
    else:
        return render_template('edititem.html', categories=categories, item=editedItem)


# Allows creator of Item to Delete Item and Deletes it from database
@app.route('/catalog/<int:category_id>/<category_name>/<item_name>/delete', methods = ['GET','POST'])
def deleteItem(category_id, category_name, item_name):
    try:
        if 'username' not in login_session:
            return redirect(url_for('showLogin'))
    except KeyError:
        return redirect(url_for('showLogin'))

    try:
        itemToDelete = session.query(Item).filter_by(category_id=category_id, name=item_name).one()
    except NoResultFound:
        flash("Invalid url")
        return redirect(url_for('showItems', category_id=category_id, category_name=category_name))
    if itemToDelete.user_id != login_session['user_id']:
        flash("You are not allowed to edit this item.")
        return redirect(url_for('showItems', category_id=category_id, category_name=category_name))

    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showItems', category_id=category_id, category_name=category_name))
    else:
        return render_template('deleteitem.html', item=itemToDelete, category_id=category_id, category_name=category_name)


# Get User Id from User email address
def getUserId(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# Get User Info using User Id
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Create new user when user logs in for first time
def createUser(login_ses):
    newUser = User(name=login_ses['username'], email=login_ses['email'],
                   picture=login_ses['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_ses['email']).one()
    return user.id


if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host='0.0.0.0', port=8000)