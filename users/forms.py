from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm

from .models import Profile


class RegisterForm(UserCreationForm):
    
    first_name = forms.CharField(max_length=100,required=False,widget=forms.TextInput(attrs={'placeholder': 'First Name','class': 'form-control',}))
    last_name = forms.CharField(max_length=100, required=False, widget=forms.TextInput(attrs={'placeholder': 'Last Name','class': 'form-control',}))
    username = forms.CharField(max_length=100,required=True,widget=forms.TextInput(attrs={'placeholder': 'Username','class': 'form-control',}))
    email = forms.EmailField(required=True,widget=forms.TextInput(attrs={'placeholder': 'Email','class': 'form-control',}))
    password1 = forms.CharField(max_length=50,required=True,widget=forms.PasswordInput(attrs={'placeholder': 'Password','class': 'form-control','data-toggle': 'password','id': 'password',}))
    password2 = forms.CharField(max_length=50,required=True, widget=forms.PasswordInput(attrs={'placeholder': 'Confirm Password','class': 'form-control','data-toggle': 'password','id': 'password',}))
    phone_number = forms.CharField(max_length=99999999999999999999,required=False,widget=forms.TextInput(attrs={'placeholder': 'Phone Number'}))
    address = forms.CharField(max_length=200,required=False,widget=forms.TextInput(attrs={'placeholder': 'address'}))
    location = forms.CharField(max_length=200, required=False, widget=forms.TextInput(attrs={'placeholder': 'Location'}))
    date_of_birth = forms.DateField(required=False, widget=forms.TextInput(attrs={'placeholder': 'Date of Birth'}))
    otp = forms.IntegerField( required=False )
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'username', 'email', 'password1', 'password2']


class LoginForm(AuthenticationForm):
    email = forms.EmailField(required=False,widget=forms.TextInput(attrs={'placeholder': 'Email','class': 'form-control',}))
    username = forms.CharField(max_length=100,required=False,widget=forms.TextInput(attrs={'placeholder': 'Username','class': 'form-control',}))
    password = forms.CharField(max_length=50,required=True,widget=forms.PasswordInput(attrs={'placeholder': 'Password','class': 'form-control','data-toggle': 'password','id': 'password','name': 'password',}))
    remember_me = forms.BooleanField(required=False)

    class Meta:
        model = User
        fields = ['email' 'password', 'remember_me']


class UpdateUserForm(forms.ModelForm):
    username = forms.CharField(max_length=100,required=True,widget=forms.TextInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(required=True,widget=forms.TextInput(attrs={'class': 'form-control'}))
    phone_number = forms.CharField(max_length=99999999999999999999,required=True,widget=forms.TextInput(attrs={'placeholder': 'Phone Number'}))
    address = forms.CharField(max_length=200,required=True,widget=forms.TextInput(attrs={'placeholder': 'address'}))
    # otp = forms.CharField(max_length=6, required=False , default='')

    class Meta:
        model = User
        fields = ['username', 'email', 'address','phone_number']


class UpdateProfileForm(forms.ModelForm):
    first_name = forms.CharField(max_length=100,required=False,widget=forms.TextInput(attrs={'placeholder': 'First Name','class': 'form-control',}))
    last_name = forms.CharField(max_length=100, required=False, widget=forms.TextInput(attrs={'placeholder': 'Last Name','class': 'form-control',}))
    avatar = forms.ImageField(required=True,widget=forms.FileInput(attrs={'class': 'form-control-file'}))
    bio = forms.CharField(required=False,widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 5}))
    email = forms.EmailField(required=True,widget=forms.TextInput(attrs={'class': 'form-control'}))
    username = forms.CharField(max_length=100,required=True,widget=forms.TextInput(attrs={'class': 'form-control'}))
    phone = forms.CharField(max_length=99999999999999999999,required=True,widget=forms.TextInput(attrs={'placeholder': 'Phone Number'}))
    phone_number = forms.CharField(max_length=11,required=True,widget=forms.TextInput(attrs={'placeholder': 'Phone Number'}))
    address = forms.CharField(max_length=200,required=True,widget=forms.TextInput(attrs={'placeholder': 'address'}))
    location = forms.CharField(max_length=200, required=False, widget=forms.TextInput(attrs={'placeholder': 'Location'}))
    date_of_birth = forms.DateField(required=False, widget=forms.TextInput(attrs={'placeholder': 'Date of Birth'}))


    class Meta:
        model = Profile
        fields = ['avatar','username', 'address','phone_number']
