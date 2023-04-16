import pytest
from django.urls import reverse

from user.enums import SystemRoleEnum
from .conftest import api_client_with_credentials


pytestmark = pytest.mark.django_db


class TestUser:
    user_list_url = reverse("user:user-list")

    def test_admin_retrieve_all_users(self, api_client, user_factory, authenticate_user):
        user_factory.create_batch(3)
        user = authenticate_user(roles=[SystemRoleEnum.ADMIN])
        token = user['token']
        api_client_with_credentials(token, api_client)
        response = api_client.get(self.user_list_url)
        assert response.status_code == 200
        assert response.json()['total'] == 4  # 3 users + admin

    @pytest.mark.parametrize(
        'user_roles',
        [
            [SystemRoleEnum.REGULAR],
        ]
    )
    def test_nonadmin_retrieve_data(self, api_client, user_roles, user_factory, authenticate_user):
        """Non admin retrieves only their data """
        user_factory.create_batch(3)
        user = authenticate_user(roles=user_roles)
        token = user['token']
        api_client_with_credentials(token, api_client)
        response = api_client.get(self.user_list_url)
        assert response.status_code == 200
        assert response.json()['total'] == 1

    def test_admin_update_all_users(self, api_client, seed_roles, user_factory, authenticate_user):
        seed_roles(role_names=[SystemRoleEnum.REGULAR])
        app_user = user_factory(firstname="First")
        user = authenticate_user(roles=[SystemRoleEnum.ADMIN])
        token = user['token']
        data = {
            "firstname": "Nike"
        }
        api_client_with_credentials(token, api_client)
        url = reverse("user:user-detail", kwargs={"pk": app_user.id})
        response = api_client.patch(url, data)
        assert response.status_code == 200
        assert response.json()['firstname'] == data["firstname"]

    def test_admin_delete_user(self, api_client, user_factory, authenticate_user):
        app_user = user_factory(firstname="First")
        user = authenticate_user(roles=[SystemRoleEnum.ADMIN])
        token = user['token']
        api_client_with_credentials(token, api_client)
        url = reverse("user:user-detail", kwargs={"pk": app_user.id})
        response = api_client.delete(url)
        assert response.status_code == 204

    @pytest.mark.parametrize(
        'user_roles',
        [
            [SystemRoleEnum.REGULAR],
        ]
    )
    def test_deny_delete_to_nonadmin(self, api_client, user_factory, user_roles, authenticate_user):
        app_user = user_factory(firstname="First")
        user = authenticate_user(roles=user_roles)
        token = user['token']
        api_client_with_credentials(token, api_client)
        url = reverse("user:user-detail", kwargs={"pk": app_user.id})
        response = api_client.delete(url)
        assert response.status_code == 403

    @pytest.mark.parametrize(
        'user_roles',
        [
            [SystemRoleEnum.REGULAR],
        ]
    )
    def test_non_admin_update_personal_data(self, api_client, user_factory, user_roles, authenticate_user):
        """Non Admin can only update their own info"""
        user = authenticate_user(roles=user_roles)
        user_instance = user['user_instance']
        token = user['token']
        data = {
            "firstname": "Nike"
        }
        api_client_with_credentials(token, api_client)
        url = reverse("user:user-detail", kwargs={"pk": user_instance.id})
        response = api_client.patch(url, data)
        assert response.status_code == 200
        assert response.json()['firstname'] == data["firstname"]
