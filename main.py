from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel, EmailStr, Field
from fastapi import FastAPI, Depends, HTTPException, status
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import List, Optional
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig

# FastAPI app
app = FastAPI()

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = "wjknLNKSLNKWDKLQDMK;1WLM;kl;mcwncdhwhichjerhchje728732ye8j22dcjhy"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    tasks = relationship("Task", back_populates="owner")
    subscriptions = relationship("ReportSubscription", back_populates="user")

class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    start_date = Column(DateTime, nullable=True)
    due_date = Column(DateTime, nullable=True)
    completion_date = Column(DateTime, nullable=True)
    status = Column(String, nullable=False, default="Pending")
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="tasks")

class ReportSubscription(Base):
    __tablename__ = "report_subscriptions"
    id = Column(Integer, primary_key=True, index=True)
    start_date = Column(DateTime, nullable=False)
    frequency = Column(String, nullable=False)
    report_time = Column(Integer, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="subscriptions")

Base.metadata.create_all(bind=engine)

# Pydantic models
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    name: str
    email: EmailStr

    class Config:
        orm_mode = True

class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = None
    start_date: Optional[datetime] = None
    due_date: Optional[datetime] = None
    completion_date: Optional[datetime] = None
    status: str = "Pending"

class TaskOut(BaseModel):
    id: int
    title: str
    description: Optional[str] = None
    start_date: Optional[datetime] = None
    due_date: Optional[datetime] = None
    completion_date: Optional[datetime] = None
    status: str

    class Config:
        orm_mode = True

class ReportSubscriptionCreate(BaseModel):
    start_date: datetime
    frequency: str
    report_time: int = Field(..., ge=0, le=23)

class ReportSubscriptionOut(BaseModel):
    id: int
    start_date: datetime
    frequency: str
    report_time: int

    class Config:
        orm_mode = True

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Authentication and authorization
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(db, email: str):
    return db.query(User).filter(User.email == email).first()

def authenticate_user(db, email: str, password: str):
    user = get_user(db, email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(db, email=email)
    if user is None:
        raise credentials_exception
    return user

def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

from collections import deque

# Initialize a deque to keep track of deleted tasks
deleted_tasks = deque(maxlen=10)

# User registration
@app.post("/users/", response_model=UserOut)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    db_user = User(name=user.name, email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Token endpoint
@app.post("/token", response_model=dict)
def login_for_access_token(db: Session = Depends(get_db), form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Task management endpoints
@app.post("/tasks/", response_model=TaskOut)
def create_task(task: TaskCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    db_task = Task(**task.dict(), owner_id=current_user.id)
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task

@app.get("/tasks/", response_model=List[TaskOut])
def read_tasks(skip: int = 0, limit: int = 10, status: Optional[str] = None, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    query = db.query(Task).filter(Task.owner_id == current_user.id)
    if status:
        query = query.filter(Task.status == status)
    if start_date and end_date:
        query = query.filter(Task.due_date.between(start_date, end_date))
    tasks = query.offset(skip).limit(limit).all()
    return tasks

@app.get("/tasks/{task_id}", response_model=TaskOut)
def read_task(task_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    task = db.query(Task).filter(Task.id == task_id, Task.owner_id == current_user.id).first()
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task

@app.put("/tasks/{task_id}", response_model=TaskOut)
def update_task(task_id: int, task: TaskCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    db_task = db.query(Task).filter(Task.id == task_id, Task.owner_id == current_user.id).first()
    if db_task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    for key, value in task.dict().items():
        setattr(db_task, key, value)
    db.commit()
    db.refresh(db_task)
    return db_task

@app.delete("/tasks/{task_id}", response_model=TaskOut)
def delete_task(task_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    db_task = db.query(Task).filter(Task.id == task_id, Task.owner_id == current_user.id).first()
    if db_task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    deleted_tasks.append(db_task)  # Track the deleted task
    db.delete(db_task)
    db.commit()
    return db_task

@app.delete("/tasks/batch_delete", response_model=List[TaskOut])
def batch_delete_tasks(start_date: datetime, end_date: datetime, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    tasks = db.query(Task).filter(Task.owner_id == current_user.id, Task.due_date.between(start_date, end_date)).all()
    for task in tasks:
        deleted_tasks.append(task)  # Track the deleted task
        db.delete(task)
    db.commit()
    return tasks


@app.post("/tasks/restore_last_deleted", response_model=TaskOut)
def restore_last_deleted_task(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if not deleted_tasks:
        raise HTTPException(status_code=404, detail="No deleted tasks to restore")
    last_deleted_task = deleted_tasks.pop()
    if last_deleted_task.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="You do not have permission to restore this task")
    db.add(last_deleted_task)
    db.commit()
    db.refresh(last_deleted_task)
    return last_deleted_task

# Report subscription endpoints
@app.post("/subscriptions/", response_model=ReportSubscriptionOut)
def create_subscription(subscription: ReportSubscriptionCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    db_subscription = ReportSubscription(**subscription.dict(), user_id=current_user.id)
    db.add(db_subscription)
    db.commit()
    db.refresh(db_subscription)
    return db_subscription

@app.delete("/subscriptions/", response_model=ReportSubscriptionOut)
def delete_subscription(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    db_subscription = db.query(ReportSubscription).filter(ReportSubscription.user_id == current_user.id).first()
    if db_subscription is None:
        raise HTTPException(status_code=404, detail="Subscription not found")
    db.delete(db_subscription)
    db.commit()
    return db_subscription

# Email scheduling
conf = ConnectionConfig(
    MAIL_USERNAME="trueyoussef@gmail.com",
    MAIL_PASSWORD="lmxmrfkxeojvigst",
    MAIL_FROM="trueyoussef@gmail.com",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True
)

def send_email_summary():
    with SessionLocal() as db:
        users = db.query(User).all()
        for user in users:
            subscriptions = db.query(ReportSubscription).filter(ReportSubscription.user_id == user.id).all()
            for subscription in subscriptions:
                if subscription.frequency == "daily":
                    start_date = datetime.utcnow() - timedelta(days=1)
                elif subscription.frequency == "weekly":
                    start_date = datetime.utcnow() - timedelta(weeks=1)
                elif subscription.frequency == "monthly":
                    start_date = datetime.utcnow() - timedelta(days=30)
                tasks = db.query(Task).filter(Task.owner_id == user.id, Task.due_date >= start_date).all()
                task_list = "".join([f"<li>{task.title}: {task.description}</li>" for task in tasks])
                message = MessageSchema(
                    subject="Task Summary",
                    recipients=[user.email],
                    body=f"<h3>Here is your task summary:</h3><ul>{task_list}</ul>",
                    subtype="html"
                )
                fm = FastMail(conf)
                try:
                    fm.send_message(message)
                except Exception as e:
                    print(f"Failed to send email to {user.email}: {e}")

scheduler = BackgroundScheduler()
scheduler.add_job(send_email_summary, "interval", minutes=60)  # Send email every hour
scheduler.start()

@app.on_event("shutdown")
def shutdown_event():
    scheduler.shutdown()