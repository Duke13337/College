from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from database import Base


class College(Base):
    __tablename__ = "colleges"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    image_url = Column(String)
    address = Column(String)
    floor_plan_key = Column(String, default="polytech")
    rooms = relationship("Room", back_populates="college")


class Room(Base):
    __tablename__ = "rooms"
    id = Column(Integer, primary_key=True, index=True)
    number = Column(String)
    description = Column(String)
    capacity = Column(Integer)
    college_id = Column(Integer, ForeignKey("colleges.id"))
    pos_x = Column(Integer, default=50)
    pos_y = Column(Integer, default=50)
    zone_w = Column(Integer, default=14)
    zone_h = Column(Integer, default=20)
    room_status = Column(String, default="available")
    is_under_maintenance = Column(Boolean, default=False)
    college = relationship("College", back_populates="rooms")
    bookings = relationship("Booking", back_populates="room")


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False, index=True)
    # Колонка в SQLite исторически называлась password — храним только PBKDF2-хэш.
    password_hash = Column("password", String, nullable=False)
    role = Column(String, nullable=False)

    bookings = relationship("Booking", back_populates="user", foreign_keys="Booking.user_id")


class Booking(Base):
    """Заявка на бронирование аудитории."""

    __tablename__ = "bookings"
    id = Column(Integer, primary_key=True, index=True)
    room_id = Column(Integer, ForeignKey("rooms.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    starts_at = Column(DateTime, nullable=False)
    ends_at = Column(DateTime, nullable=False)
    status = Column(String, default="pending", nullable=False)  # pending | confirmed | cancelled
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    reviewed_at = Column(DateTime, nullable=True)
    reviewed_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    room = relationship("Room", back_populates="bookings")
    user = relationship("User", back_populates="bookings", foreign_keys=[user_id])
    reviewer = relationship("User", foreign_keys=[reviewed_by_id])
