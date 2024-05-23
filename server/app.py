#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    
    def post(self):
        json = request.get_json()
        try:
            user = User(
                username = json.get("username"),
                image_url = json.get("image_url"),
                bio = json.get("bio")
            )
            user.password_hash = json.get("password")
            session["user_id"] = user.id
            db.session.add(user)
            db.session.commit()
            return user.to_dict(), 201
        except IntegrityError:
            return {"error": "User information invalid"}, 422
        except ValueError:
            return {"error": "User information invalid"}, 422

class CheckSession(Resource):

    def get(self):
        if session["user_id"]:
            user = User.query.filter(User.id == session["user_id"]).first()
            return user.to_dict(), 200
        return {"error": "Unauthorized"}, 401


class Login(Resource):
    def post(self):

        try:
            username = request.get_json().get("username")
            user = User.query.filter(User.username == username).first()
            password = request.get_json().get("password")
            user.authenticate(password)
            session["user_id"] = user.id
            return user.to_dict(), 200
        except:
            return {"error": "Unauthorized username and/or password"}, 401


class Logout(Resource):
    def delete(self):
        if session["user_id"]:
            session["user_id"] = None
            return {"message": "204: No Content"}, 204
        return {"error": "User not logged in"}, 401


class RecipeIndex(Resource):
    def get(self):
        if session["user_id"]:
            recipes = [recipe.to_dict(rules = ("user",)) for recipe in Recipe.query.all()]
            return recipes, 200
        return {"error": "User not logged in"}, 401

    def post(self):
        if session["user_id"]:
            recipe_data = request.get_json()
            try:
                new_recipe = Recipe(
                title = recipe_data.get("title"),
                instructions = recipe_data.get("instructions"),
                minutes_to_complete = recipe_data.get("minutes_to_complete"),
                user_id = session["user_id"]    
                )
                db.session.add(new_recipe)
                db.session.commit()

                return new_recipe.to_dict(rules = ("user",)), 201
            except IntegrityError:
                return {"error": "Recipe information invalid"}, 422


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)