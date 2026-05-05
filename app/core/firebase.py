import firebase_admin
from firebase_admin import credentials, auth

cred = credentials.Certificate("C:\Users\yogis\Desktop\Learn\serviceAccountKey.json")

firebase_admin.initialize_app(cred)