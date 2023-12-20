from django.urls import path
from post.views import (PostListAPIView, PostCreateAPIView, PostRetrieveUpdateDestroyView, PostCommentListView,
                        PostCommentCreateView, CommentCreateView, CommentListCreateView, PostLikeListView, CommentRetrieveView,
                        CommentLikeListView, PostLikeAPIView, CommentLikeAPIView, PostLikingAPIView, CommentLikingAPIView)



urlpatterns = [
    path('lists/', PostListAPIView.as_view(), name='post-list'),
    path('create/', PostCreateAPIView.as_view(), name='post-create'),
    path('<uuid:id>/', PostRetrieveUpdateDestroyView.as_view(), name='post-retrieve-update-destroy'),
    path('<uuid:id>/comment/list/', PostCommentListView.as_view(), name='post-comment-list'),
    path('<uuid:id>/like/list', PostLikeListView.as_view(), name='post-like-list'),
    path('comments/', CommentListCreateView.as_view(), name='comment-create-list'),

    path('<uuid:id>/comment/create/', PostCommentCreateView.as_view(), name='post-comment-create'),
    path('comment-create/', CommentCreateView.as_view(), name='comment-create'),
    
    path('<uuid:pk>/liking/', PostLikeAPIView.as_view(), name='post-liking'),
    path('<uuid:pk>/like/', PostLikingAPIView.as_view(), name='post-like'),

    path('comments/<uuid:id>/', CommentRetrieveView.as_view(), name='comment-retrieve'),
    path('comments/<uuid:id>/likes', CommentLikeListView.as_view(), name='comment-likes'),
    path('comments/<uuid:pk>/liking/', CommentLikeAPIView.as_view(), name='comment-liking'),
    path('comments/<uuid:pk>/liking/create', CommentLikingAPIView.as_view(), name='comment-liking-create'),
]
