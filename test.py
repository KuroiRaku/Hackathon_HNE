from flask import Flask, render_template, url_for, request, flash, current_app, redirect, session
from flask_wtf import FlaskForm
from wtforms import TextField, TextAreaField, SubmitField, SelectField, ValidationError, StringField, PasswordField, BooleanField, IntegerField, FileField
from flask_wtf.file import FileField, FileRequired
from wtforms.validators import InputRequired, Email, DataRequired, Length, EqualTo
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY']='123456789_ABC'
db=SQLAlchemy(app)

class Test(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    PhotoUrl = db.Column(db.String(30))
    Integer = db.Column(db.Integer)

class PhotoForm(FlaskForm):
    photo = FileField(validators=[FileRequired()])
    integer = IntegerField(validators=[InputRequired()])


bootstrap = Bootstrap(app)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    form=PhotoForm()
    if form.validate_on_submit():
        f = form.photo.data
        filename = secure_filename(f.filename)
        f.save(os.path.join(
            os.path.dirname(__file__), 'database/images', filename
        ))
        file_url= os.path.join(
            os.path.dirname(__file__), 'database/images', filename
        )

        new_test = Test(PhotoUrl=file_url, Integer=form.integer.data)
        db.session.add(new_test)
        db.session.commit()
        return "file url:"+file_url

    return render_template('test.html', form=form)

if __name__=="__main__":
    db.create_all()
    app.run(debug=True)
