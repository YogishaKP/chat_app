# Request Body Validation
class UserData(BaseModel):
    name: str
    age: int

@app.post("/user_1")
def create_user(user: UserData):
    return user

# Response Modeling
class UserResponse(BaseModel):
    id: int
    name: str

@app.get("/user_2/{id}",response_model=UserResponse)
def get_user(id: int):
    return {
        "id": id,
        "name": "Alice",
        "password": "secret"
    }

# Default Values
class DefaultV(BaseModel):
    name: str
    balance: float=0.0

@app.post("/user_3")
def defa_val(user: DefaultV):
    return user

# Optional Fields
