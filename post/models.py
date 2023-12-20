from django.db import models
from django.contrib.auth import get_user_model
from shared.models import BaseModel
from django.core.validators import FileExtensionValidator, MaxLengthValidator
from django.db.models import UniqueConstraint

User = get_user_model()


class Post(BaseModel):
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='posts')
    image = models.ImageField(upload_to='posts/', validators=[FileExtensionValidator(allowed_extensions=['jpeg', 'jpg', 'png'])])
    caption = models.TextField(validators=[MaxLengthValidator(2000)])


    class Meta:
        db_table = 'posts'
        verbose_name = 'post'
        verbose_name_plural = 'posts'
        ordering = ['-created_time']

    def __str__(self):
        return f"{self.author} - {self.caption}"
        

class PostCommet(BaseModel):
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    comment = models.TextField()
    parent = models.ForeignKey('self', on_delete=models.CASCADE, related_name='child', null=True, blank=True)

    class Meta:
        db_table = 'comments'
        verbose_name = 'comment'
        verbose_name_plural = 'comments'
        ordering = ['-created_time']

    def __str__(self):
        return f"{self.author} - {self.post}"



class PostLike(BaseModel):
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='likes')

    class Meta:
        db_table = 'post_likes'
        verbose_name = 'post_like'
        verbose_name_plural = 'post_likes'
        ordering = ['-created_time']
        constraints  = [
            UniqueConstraint(
                fields = ['author', 'post'], name='unique_post_likes'
            ),
        ]
    
    def __str__(self):
        return f"{self.author} - {self.post}"
    


class CommentLike(BaseModel):
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    comment = models.ForeignKey(PostCommet, on_delete=models.CASCADE, related_name='likes')

    class Meta:
        db_table = 'comment_likes'
        verbose_name = 'comment_like'
        verbose_name_plural = 'comment_likes'
        ordering = ['-created_time']
        constraints  = [
            UniqueConstraint(
                fields = ['author', 'comment'], name='unique_comment_likes'
            )
        ]
    
    def __str__(self):
        return f"{self.author} - {self.comment}"