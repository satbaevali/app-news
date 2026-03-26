from  django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password  
from .models import User
from rest_framework import serializers


class UserRegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.

    """
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        validators=[validate_password]
    )
    password_confirm = serializers.CharField(
        write_only=True,
        required=True
    )
    class Meta :
        model = User
        fields = (
            'username',
          
            'email',
            'first_name',
            'last_name',
            'password',
            'password_confirm',
            
        )

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password_confirm": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user
    
    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        password_confirm = validated_data.pop('password_confirm', None)

        if password and password_confirm:
            if password != password_confirm:
                raise serializers.ValidationError({"password_confirm": "Password fields didn't match."})
            instance.set_password(password)

        return super().update(instance, validated_data)
    

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(
        required=True
    )
    password = serializers.CharField(
        write_only=True,
        required=True
    )
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            user = authenticate(
                request=self.context.get('request'),
                username=email,
                password=password      
                )
            if not user:
                raise serializers.ValidationError("Invalid email or password.")
            if not user.is_active:
                raise serializers.ValidationError("User account is disabled.")
            attrs['user'] = user
            return attrs
        else:
            raise serializers.ValidationError("Both email and password are required.")

class UserProfileSerializer(serializers.ModelSerializer):
    full_name = serializers.ReadOnlyField()
    posts_counts = serializers.SerializerMethodField()
    comments_counts = serializers.SerializerMethodField()
    class Meta:
        model = User
        fields = (
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'full_name',
            'avatar',
            'bio',
            'created_at',
            'updated_at',
            'posts_counts',
            'comments_counts',

        )
        read_only_fields = ('id', 'created_at', 'updated_at')


    def get_posts_counts(self, obj):
        try:
            return obj.posts.count()
        except AttributeError:
            return 0
    
    def get_comments_counts(self, obj):
        try:
            return obj.comments.count()
        except AttributeError:
            return 0

class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            'first_name',
            'last_name',    
            'avatar',
            'bio',
        )
    
    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance
    
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(
        write_only=True,
        required=True
    )
    new_password = serializers.CharField(
        write_only=True,
        required=True,
        validators=[validate_password]
    )
    new_password_confirm = serializers.CharField(
        write_only=True,
        required=True
    )

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({"new_password_confirm": "New password fields didn't match."})
        return attrs
    
    def save(self, **kwargs):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user