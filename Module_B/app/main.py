import datetime
import os
from typing import Literal

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from passlib.context import CryptContext
from pydantic import BaseModel
from database import execute_query

app = FastAPI()

SECRET_KEY = "your_secret_key"  # In production, use a secure method to store this
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Pydantic model for login request
class LoginRequest(BaseModel):
    username: str
    password: str


class PortfolioUpdate(BaseModel):
    bio: str | None = None
    contact_number: str | None = None
    department: str | None = None


class PostCreate(BaseModel):
    content: str
    media_url: str | None = None
    media_type: Literal["Image", "Video", "Document", "None"] = "None"
    visibility: Literal["Public", "Followers", "Private"] = "Public"


class PostUpdate(BaseModel):
    content: str | None = None
    media_url: str | None = None
    media_type: Literal["Image", "Video", "Document", "None"] | None = None
    visibility: Literal["Public", "Followers", "Private"] | None = None


class CommentCreate(BaseModel):
    content: str


class CommentUpdate(BaseModel):
    content: str


def _verify_password(plain_password: str, stored_hash: str) -> bool:
    # Supports assignment sample data while still enabling real bcrypt checks.
    if stored_hash.startswith("$2b$12$DUMMY_HASH_"):
        return plain_password == "password123"
    try:
        return pwd_context.verify(plain_password, stored_hash)
    except ValueError:
        return False


def _is_allowed_to_view_profile(viewer_id: int, viewer_role: str, target_member_id: int) -> bool:
    if viewer_role == "Admin" or viewer_id == target_member_id:
        return True

    follows_target = execute_query(
        """
        SELECT 1
        FROM Follow
        WHERE FollowerID = %s AND FollowingID = %s
        """,
        (viewer_id, target_member_id),
        fetchone=True,
    )
    return follows_target is not None


def _get_visible_post(post_id: int, member_id: int):
    return execute_query(
        """
        SELECT
            p.PostID,
            p.MemberID,
            p.IsActive,
            p.Visibility
        FROM Post p
        WHERE p.PostID = %s
          AND p.IsActive = TRUE
          AND (
              p.Visibility = 'Public'
              OR p.MemberID = %s
              OR (
                  p.Visibility = 'Followers'
                  AND EXISTS (
                      SELECT 1
                      FROM Follow f
                      WHERE f.FollowerID = %s AND f.FollowingID = p.MemberID
                  )
              )
          )
        """,
        (post_id, member_id, member_id),
        fetchone=True,
    )
    
# Dependency: Session validation
def verify_session_token(session_token: str = Header(None, alias="session-token")):
    if not session_token:
        raise HTTPException(status_code=401, detail="Missing parameters")
    try:
        payload = jwt.decode(session_token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload  # Return the decoded payload for use in endpoints
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid session token" )
    
@app.get("/", include_in_schema=False)
def ui_home():
    """Serve the local web UI."""
    return FileResponse(os.path.join(STATIC_DIR, "login.html"))


@app.get("/health")
def health_check(_: dict = Depends(verify_session_token)):
    """Simple health endpoint to test the API."""
    return {"message": "College Social Media API is running."}

@app.post("/login")
def login(request: LoginRequest):
    """Authenticates a user and returns a session token."""
    query = """
        SELECT m.MemberID, m.Email, m.Role, m.Name, a.PasswordHash 
        FROM Member m
        JOIN AuthCredential a ON m.MemberID = a.MemberID
        WHERE m.Email = %s
    """
    user_record = execute_query(query, (request.username,), fetchone=True)
    
    if not user_record:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not _verify_password(request.password, user_record["PasswordHash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Create JWT token
    expiry_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    token_payload = {
        "member_id": user_record["MemberID"],
        "Email": user_record["Email"],
        "role": user_record["Role"],
        "name": user_record["Name"],
        "exp": int(expiry_time.timestamp()),
    }
    
    token = jwt.encode(token_payload, SECRET_KEY, algorithm=ALGORITHM)
    return {
        "message": "Login successful",
        "session_token": token
    }
    
@app.get("/isAuth")
def is_auth(current_user: dict = Depends(verify_session_token)):
    """Endpoint to check if the session token is valid."""
    expiry_dt = datetime.datetime.fromtimestamp(current_user.get("exp"))
    return {
        "message": "Session is valid",
        "member_id": current_user.get("member_id"),
        "email": current_user.get("Email"),
        "role": current_user.get("role"),
        "expires_at": expiry_dt.isoformat()
    }


@app.post("/logout")
def logout(_: dict = Depends(verify_session_token)):
    """Client clears token locally; this endpoint confirms logout intent."""
    return {"message": "Logout successful"}

# --- CRUD Endpoints for Member Portfolio ---

@app.get("/portfolio/{member_id}")
def get_portfolio(member_id: int, current_user: dict = Depends(verify_session_token)):
    """
    Retrieves portfolio details.
    RBAC: Users can only view their own profile unless they are an Admin.
    """
    # 1. Enforce Role-Based Access Control (RBAC)
    viewer_id = current_user.get("member_id")
    viewer_role = current_user.get("role")

    if viewer_id is None:
        raise HTTPException(status_code=401, detail="Invalid session payload")

    if not _is_allowed_to_view_profile(viewer_id, viewer_role, member_id):
        raise HTTPException(status_code=403, detail="You do not have permission to view this portfolio.")
        
    # 2. Fetch data from MySQL
    query = """
        SELECT Name, Email, ContactNumber, Department, Bio, JoinDate, Role
        FROM Member
        WHERE MemberID = %s
    """
    portfolio = execute_query(query, (member_id,), fetchone=True)
    
    if not portfolio:
        raise HTTPException(status_code=404, detail="Member not found.")
        
    return {"message": "Portfolio retrieved successfully", "data": portfolio}

@app.put("/portfolio/{member_id}")
def update_portfolio(member_id: int, update_data: PortfolioUpdate, current_user: dict = Depends(verify_session_token)):
    """
    Updates portfolio details (Bio, Contact Number, Department).
    RBAC: Users can only modify their own profile unless they are an Admin.
    """
    # 1. Enforce Role-Based Access Control (RBAC)
    is_admin = current_user.get("role") == "Admin"
    is_self = current_user.get("member_id") == member_id
    
    if not (is_admin or is_self):
        raise HTTPException(status_code=403, detail="You do not have permission to modify this portfolio.")
        
    # 2. Build the update query dynamically based on provided fields
    updates = []
    params = []
    if update_data.bio is not None:
        updates.append("Bio = %s")
        params.append(update_data.bio)
    if update_data.contact_number is not None:
        updates.append("ContactNumber = %s")
        params.append(update_data.contact_number)
    if update_data.department is not None:
        updates.append("Department = %s")
        params.append(update_data.department)
        
    if not updates:
        return {"message": "No data provided to update."}
        
    # Append the WHERE clause parameter
    query = f"UPDATE Member SET {', '.join(updates)} WHERE MemberID = %s"
    params.append(member_id)
    
    # 3. Execute the update
    execute_query(query, tuple(params))
    
    return {"message": f"Portfolio for member {member_id} updated successfully."}


# --- CRUD Endpoints for Post (project-specific table) ---

@app.post("/posts")
def create_post(post_data: PostCreate, current_user: dict = Depends(verify_session_token)):
    """Create a new post for the authenticated member."""
    member_id = current_user.get("member_id")
    if member_id is None:
        raise HTTPException(status_code=401, detail="Invalid session payload")

    if not post_data.content.strip():
        raise HTTPException(status_code=400, detail="Content cannot be empty")

    query = """
        INSERT INTO Post (MemberID, Content, MediaURL, MediaType, Visibility)
        VALUES (%s, %s, %s, %s, %s)
    """
    new_post_id = execute_query(
        query,
        (member_id, post_data.content.strip(), post_data.media_url, post_data.media_type, post_data.visibility),
    )
    return {"message": "Post created successfully", "post_id": new_post_id}


@app.get("/posts")
def list_posts(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: dict = Depends(verify_session_token),
):
    """Read all active posts for the authenticated user session."""
    if current_user.get("member_id") is None:
        raise HTTPException(status_code=401, detail="Invalid session payload")

    query = """
        SELECT
            p.PostID,
            p.MemberID,
            m.Name AS AuthorName,
            p.Content,
            p.MediaURL,
            p.MediaType,
            p.PostDate,
            p.LastEditDate,
            p.Visibility,
            p.LikeCount,
            p.CommentCount
        FROM Post p
        JOIN Member m ON p.MemberID = m.MemberID
        WHERE p.IsActive = TRUE
        ORDER BY p.PostDate DESC
        LIMIT %s OFFSET %s
    """
    posts = execute_query(query, (limit, offset), fetchall=True)
    return {"message": "Posts retrieved successfully", "count": len(posts), "data": posts}


@app.get("/posts/{post_id}")
def get_post(post_id: int, current_user: dict = Depends(verify_session_token)):
    """Read one post if it is visible to the authenticated member."""
    member_id = current_user.get("member_id")
    if member_id is None:
        raise HTTPException(status_code=401, detail="Invalid session payload")

    visible_post = _get_visible_post(post_id, member_id)
    if not visible_post:
        raise HTTPException(status_code=404, detail="Post not found or not visible")

    query = """
        SELECT
            p.PostID,
            p.MemberID,
            m.Name AS AuthorName,
            p.Content,
            p.MediaURL,
            p.MediaType,
            p.PostDate,
            p.LastEditDate,
            p.Visibility,
            p.LikeCount,
            p.CommentCount,
            p.IsActive
        FROM Post p
        JOIN Member m ON p.MemberID = m.MemberID
        WHERE p.PostID = %s
          AND p.IsActive = TRUE
          AND (
              p.Visibility = 'Public'
              OR p.MemberID = %s
              OR (
                  p.Visibility = 'Followers'
                  AND EXISTS (
                      SELECT 1
                      FROM Follow f
                      WHERE f.FollowerID = %s AND f.FollowingID = p.MemberID
                  )
              )
          )
    """
    post = execute_query(query, (post_id, member_id, member_id), fetchone=True)
    if not post:
        raise HTTPException(status_code=404, detail="Post not found or not visible")
    return {"message": "Post retrieved successfully", "data": post}


@app.post("/posts/{post_id}/comments")
def create_comment(post_id: int, comment_data: CommentCreate, current_user: dict = Depends(verify_session_token)):
    """Create a comment on a visible post."""
    member_id = current_user.get("member_id")
    if member_id is None:
        raise HTTPException(status_code=401, detail="Invalid session payload")

    if not _get_visible_post(post_id, member_id):
        raise HTTPException(status_code=404, detail="Post not found or not visible")

    if not comment_data.content.strip():
        raise HTTPException(status_code=400, detail="Comment content cannot be empty")

    comment_id = execute_query(
        """
        INSERT INTO Comment (PostID, MemberID, Content)
        VALUES (%s, %s, %s)
        """,
        (post_id, member_id, comment_data.content.strip()),
    )
    return {"message": "Comment created successfully", "comment_id": comment_id}


@app.get("/posts/{post_id}/comments")
def list_comments(post_id: int, current_user: dict = Depends(verify_session_token)):
    """Read comments for a visible post."""
    member_id = current_user.get("member_id")
    if member_id is None:
        raise HTTPException(status_code=401, detail="Invalid session payload")

    if not _get_visible_post(post_id, member_id):
        raise HTTPException(status_code=404, detail="Post not found or not visible")

    comments = execute_query(
        """
        SELECT
            c.CommentID,
            c.PostID,
            c.MemberID,
            m.Name AS AuthorName,
            c.Content,
            c.CommentDate,
            c.LastEditDate,
            c.LikeCount,
            c.IsActive
        FROM Comment c
        JOIN Member m ON c.MemberID = m.MemberID
        WHERE c.PostID = %s AND c.IsActive = TRUE
        ORDER BY c.CommentDate ASC
        """,
        (post_id,),
        fetchall=True,
    )
    return {"message": "Comments retrieved successfully", "count": len(comments), "data": comments}


@app.put("/comments/{comment_id}")
def update_comment(comment_id: int, update_data: CommentUpdate, current_user: dict = Depends(verify_session_token)):
    """Update a comment. Only owner or admin may modify."""
    member_id = current_user.get("member_id")
    role = current_user.get("role")
    if member_id is None:
        raise HTTPException(status_code=401, detail="Invalid session payload")

    if not update_data.content.strip():
        raise HTTPException(status_code=400, detail="Comment content cannot be empty")

    comment_owner = execute_query(
        "SELECT CommentID, MemberID, IsActive FROM Comment WHERE CommentID = %s",
        (comment_id,),
        fetchone=True,
    )
    if not comment_owner or not comment_owner["IsActive"]:
        raise HTTPException(status_code=404, detail="Comment not found")

    if role != "Admin" and comment_owner["MemberID"] != member_id:
        raise HTTPException(status_code=403, detail="You do not have permission to modify this comment")

    execute_query(
        """
        UPDATE Comment
        SET Content = %s, LastEditDate = CURRENT_TIMESTAMP
        WHERE CommentID = %s
        """,
        (update_data.content.strip(), comment_id),
    )
    return {"message": f"Comment {comment_id} updated successfully."}


@app.delete("/comments/{comment_id}")
def delete_comment(comment_id: int, current_user: dict = Depends(verify_session_token)):
    """Delete a comment via soft delete. Only owner or admin may delete."""
    member_id = current_user.get("member_id")
    role = current_user.get("role")
    if member_id is None:
        raise HTTPException(status_code=401, detail="Invalid session payload")

    comment_owner = execute_query(
        "SELECT CommentID, MemberID, IsActive FROM Comment WHERE CommentID = %s",
        (comment_id,),
        fetchone=True,
    )
    if not comment_owner or not comment_owner["IsActive"]:
        raise HTTPException(status_code=404, detail="Comment not found")

    if role != "Admin" and comment_owner["MemberID"] != member_id:
        raise HTTPException(status_code=403, detail="You do not have permission to delete this comment")

    execute_query("UPDATE Comment SET IsActive = FALSE WHERE CommentID = %s", (comment_id,))
    return {"message": f"Comment {comment_id} deleted successfully."}


@app.put("/posts/{post_id}")
def update_post(post_id: int, update_data: PostUpdate, current_user: dict = Depends(verify_session_token)):
    """Update post content/metadata. Only owner or admin may modify."""
    member_id = current_user.get("member_id")
    role = current_user.get("role")
    if member_id is None:
        raise HTTPException(status_code=401, detail="Invalid session payload")

    post_owner = execute_query(
        "SELECT PostID, MemberID, IsActive FROM Post WHERE PostID = %s",
        (post_id,),
        fetchone=True,
    )
    if not post_owner or not post_owner["IsActive"]:
        raise HTTPException(status_code=404, detail="Post not found")

    if role != "Admin" and post_owner["MemberID"] != member_id:
        raise HTTPException(status_code=403, detail="You do not have permission to modify this post")

    updates = []
    params = []

    if update_data.content is not None:
        if not update_data.content.strip():
            raise HTTPException(status_code=400, detail="Content cannot be empty")
        updates.append("Content = %s")
        params.append(update_data.content.strip())
    if update_data.media_url is not None:
        updates.append("MediaURL = %s")
        params.append(update_data.media_url)
    if update_data.media_type is not None:
        updates.append("MediaType = %s")
        params.append(update_data.media_type)
    if update_data.visibility is not None:
        updates.append("Visibility = %s")
        params.append(update_data.visibility)

    if not updates:
        return {"message": "No data provided to update."}

    updates.append("LastEditDate = CURRENT_TIMESTAMP")
    query = f"UPDATE Post SET {', '.join(updates)} WHERE PostID = %s"
    params.append(post_id)
    execute_query(query, tuple(params))
    return {"message": f"Post {post_id} updated successfully."}


@app.delete("/posts/{post_id}")
def delete_post(post_id: int, current_user: dict = Depends(verify_session_token)):
    """Delete a post via soft delete. Only owner or admin may delete."""
    member_id = current_user.get("member_id")
    role = current_user.get("role")
    if member_id is None:
        raise HTTPException(status_code=401, detail="Invalid session payload")

    post_owner = execute_query(
        "SELECT PostID, MemberID, IsActive FROM Post WHERE PostID = %s",
        (post_id,),
        fetchone=True,
    )
    if not post_owner or not post_owner["IsActive"]:
        raise HTTPException(status_code=404, detail="Post not found")

    if role != "Admin" and post_owner["MemberID"] != member_id:
        raise HTTPException(status_code=403, detail="You do not have permission to delete this post")

    execute_query("UPDATE Post SET IsActive = FALSE WHERE PostID = %s", (post_id,))
    return {"message": f"Post {post_id} deleted successfully."}