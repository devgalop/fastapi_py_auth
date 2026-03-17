from datetime import timedelta
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from . import user_service, user_token, token_factory, user

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Hello World"}

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> user_token.Token:
    user = user_service.authenticate_user(user_service.load_users_db(), form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=user_service.token_factory.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = user_service.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return user_token.Token(access_token=access_token, token_type="bearer")


@app.get("/users/me/")
async def read_users_me(
    current_user: Annotated[user.User, Depends(user_service.get_current_active_user)],
) -> user.User:
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[user.User, Depends(user_service.get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.username}]