from post import serializers
from rest_framework import generics
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly, AllowAny
from post.models import CommentLike, Post, PostCommet, PostLike
from post.serializers import PostSerializer, CommentSerializer, CommentLikeSerializer, PostLikeSerializer
from shared.custom_pagination import CustomPagination
from rest_framework.views import APIView


class PostListAPIView(generics.ListAPIView):
    serializer_class = PostSerializer
    permission_classes = [AllowAny,]
    pagination_class = CustomPagination

    def get_queryset(self):
        return Post.objects.all()
    
# class PostListCreateAPIView(generics.ListCreateAPIView):
#     serializer_class = PostSerializer
#     permission_classes = [IsAuthenticatedOrReadOnly,]
#     pagination_class = CustomPagination

#     def get_queryset(self):
#         return Post.objects.all()
    
#     def perform_create(self, serializer):
#         serializer.save(author=self.request.user)
    

class PostCreateAPIView(generics.CreateAPIView):
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticated,]


    def perform_create(self, serializer):
        serializer.save(author=self.request.user)


class PostRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Post.objects.all()
    serializer_class = PostSerializer
    permission_classes = [IsAuthenticatedOrReadOnly,]


    def put(self, request, *args, **kwargs):
        post = self.get_object()
        serializer = self.serializer_class(post, data = request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {
                "success": True,
                "code":status.HTTP_200_OK,
                "message":"Post successfully updated",
                "data":serializer.data
            }
        )
    
    def delete(self, request, *args, **kwargs):
        post = self.get_object()
        post.delete()
        return Response(
            {
                "success": True,
                "code":status.HTTP_204_NO_CONTENT,
                "message":"Post successfully updated"
            }
        )


class PostCommentListView(generics.ListAPIView):
    serializer_class = CommentSerializer
    permission_classes = [AllowAny,]

    def get_queryset(self):
        post_id = self.kwargs['id']
        queryset = PostCommet.objects.filter(post__id=post_id)
        return queryset


class PostCommentCreateView(generics.CreateAPIView):
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated,]
    queryset = PostLike.objects.all()

    def perform_create(self, serializer):
        post_id = self.kwargs['id']
        serializer.save(author=self.request.user, post_id = post_id)
    

class CommentCreateView(generics.CreateAPIView):
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated, ]

    def perform_create(self, serializer):
        serializer.save(author = self.request.user)


class CommentListCreateView(generics.ListCreateAPIView):
    queryset = PostCommet.objects.all()
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticatedOrReadOnly, ]
    pagination_class = CustomPagination

    def perform_create(self, serializer):
        serializer.save(author = self.request.user)


class CommentRetrieveView(generics.RetrieveAPIView):
    serializer_class = CommentSerializer
    permission_classes = [AllowAny, ]
    queryset = PostCommet.objects.all()
    lookup_field = 'id'


class PostLikeListView(generics.ListAPIView):
    serializer_class = PostLikeSerializer
    permission_classes = [AllowAny, ]


    def get_queryset(self):
        post_id = self.kwargs['id']
        queryset = PostLike.objects.filter(post__id=post_id)
        return queryset
    

class CommentLikeListView(generics.ListAPIView):
    serializer_class = CommentLikeSerializer
    permission_classes = [AllowAny, ]


    def get_queryset(self):
        comment_id = self.kwargs['id']
        queryset = CommentLike.objects.filter(comment__id=comment_id)
        return queryset
    

class PostLikeAPIView(APIView):

    def post(self, request, pk):
        try:
            post_like = PostLike.objects.create(
                author = self.request.user,
                post_id = pk
            )
            serializer = PostLikeSerializer(post_like)
            data = {
                "success":True,
                "message":"Postga like muvaffaqiyatli qo'shildi.",
                "data": serializer.data
            }
            return Response(data, status = status.HTTP_201_CREATED)
        except Exception as e:
            data = {
                "success":False,
                "message":f"{str(e)}",
                "data": None
            }
            return Response(data, status = status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        try:
            post_like = PostLike.objects.get(
                author = self.request.user,
                post_id = pk
            )
            post_like.delete()
            data = {
                "success":True,
                "message":"Like muvaffaqiyatli o'chirildi",
                "data": None
            }
            return Response(data, status = status.HTTP_204_NO_CONTENT)
        except Exception as e:
            data = {
                "success":False,
                "message":f"{str(e)}",
                "data": None
            }
            return Response(data, status = status.HTTP_400_BAD_REQUEST)


class CommentLikeAPIView(APIView):

    def post(self, request, pk):
        try:
            comment_like = CommentLike.objects.create(
                author = self.request.user,
                comment_id = pk
            )
            serializer = CommentLikeSerializer(comment_like)
            data = {
                "success":True,
                "message":"Commentga like muvaffaqiyatli qo'shildi.",
                "data": serializer.data
            }
            return Response(data, status = status.HTTP_201_CREATED)
        except Exception as e:
            data = {
                "success":False,
                "message":f"{str(e)}",
                "data": None
            }
            return Response(data, status = status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        try:
            comment_like = CommentLike.objects.get(
                author = self.request.user,
                comment_id = pk
            )
            comment_like.delete()
            data = {
                "success":True,
                "message":"Like muvaffaqiyatli o'chirildi",
                "data": None
            }
            return Response(data, status = status.HTTP_204_NO_CONTENT)
        except Exception as e:
            data = {
                "success":False,
                "message":f"{str(e)}",
                "data": None
            }
            return Response(data, status = status.HTTP_400_BAD_REQUEST)
        


class PostLikingAPIView(APIView):

    def post(self, request, pk):
        try:
            post_like = PostLike.objects.get(
                author = self.request.user,
                post_id = pk
            )
            post_like.delete()
            data = {
                'success':True,
                "message":"Like muvaffaqiyatli o'chirildi!",

            }
            return Response(data, status = status.HTTP_204_NO_CONTENT)
        except:
            post_like = PostLike.objects.create(
                author = self.request.user,
                post_id = pk
            )
            serializer = PostLikeSerializer(post_like)
            data = {
                "success":True,
                "message":"Postga like muvaffaqiyatli qo'shildi.",
                "data": serializer.data
            }
            return Response(data, status = status.HTTP_201_CREATED)


class CommentLikingAPIView(APIView):

    def post(self, request, pk):
        try:
            comment_like = CommentLike.objects.get(
                author = self.request.user,
                comment_id = pk
            )
            comment_like.delete()
            data = {
                'success':True,
                "message":"Like muvaffaqiyatli o'chirildi!",

            }
            return Response(data, status = status.HTTP_204_NO_CONTENT)
        except:
            comment_id = CommentLike.objects.create(
                author = self.request.user,
                comment_id = pk
            )
            serializer = CommentLikeSerializer(comment_id)
            data = {
                "success":True,
                "message":"Commentga like muvaffaqiyatli qo'shildi.",
                "data": serializer.data
            }
            return Response(data, status = status.HTTP_201_CREATED)