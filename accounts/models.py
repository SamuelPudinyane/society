from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Date, Boolean, Text, ForeignKey
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.mssql import NVARCHAR, BIT, VARCHAR
from sqlalchemy.orm import relationship

Base = declarative_base()


# --- TABLE: Users ---
class Society_Users(Base):
    __tablename__ = "Users"

    user_id = Column(NVARCHAR(255), primary_key=True, nullable=False)
    first_name = Column(NVARCHAR(25), nullable=False)
    last_name = Column(NVARCHAR(25), nullable=False)
    email = Column(NVARCHAR(120), unique=True, nullable=False)
    contact_number = Column(NVARCHAR(15), nullable=False)
    occupation = Column(NVARCHAR(50), nullable=False)
    gender = Column(NVARCHAR(6), nullable=False)
    date_of_birth = Column(Date, nullable=False)
    address = Column(NVARCHAR(200), nullable=False)
    postal_code = Column(NVARCHAR(4), nullable=False)
    role = Column(NVARCHAR(15), nullable=False)
    password = Column(NVARCHAR(128), nullable=False)
    active = Column(Boolean, default=False, nullable=False)
    verified = Column(Boolean, default=False, nullable=False)

    # Relationships (must match class names & back_populates)
    profiles = relationship("Society_UserProfile", back_populates="user", cascade="all, delete-orphan")
    tokens = relationship("Society_UserToken", back_populates="user", cascade="all, delete-orphan")
    copies = relationship("Society_Copies", back_populates="user", cascade="all, delete-orphan")


# --- TABLE: Society_user_profile ---
class Society_UserProfile(Base):
    __tablename__ = "Society_user_profile"

    id = Column(NVARCHAR(36), primary_key=True, nullable=False)
    user_id = Column(NVARCHAR(255), ForeignKey("Users.user_id"), nullable=False)
    bio = Column(Text, nullable=True)
    avatar = Column(NVARCHAR(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("Society_Users", back_populates="profiles")


# --- TABLE: Society_user_token ---
class Society_UserToken(Base):
    __tablename__ = "Society_user_token"

    token = Column(VARCHAR(72), primary_key=True, nullable=False, unique=True)
    salt = Column(VARCHAR(20), nullable=True)
    expire = Column(Boolean, default=False, nullable=False)
    user_id = Column(NVARCHAR(255), ForeignKey("Users.user_id"), nullable=False)

    user = relationship("Society_Users", back_populates="tokens")


# --- TABLE: Society_copies ---
class Society_Copies(Base):
    __tablename__ = "Society_copies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    id_copy = Column(Text, nullable=True)
    certificate = Column(Text, nullable=True)
    user_id = Column(NVARCHAR(255), ForeignKey("Users.user_id"), nullable=False)

    user = relationship("Society_Users", back_populates="copies")
