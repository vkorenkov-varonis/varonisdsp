import json
import unittest
from unittest.mock import MagicMock

from phantom.action_result import ActionResult

from varonisdsp_connector import VaronisDspSaasConnector
from varonisdsp_consts import *
from varonisdsp_search import ALERT_STATUSES, CLOSE_REASONS


class VaronisDSPTest(unittest.TestCase):
    def setUp(self) -> None:
        self.connector = VaronisDspSaasConnector()
        self.connector._base_url = 'https://test.com'

    def test_handle_get_alerts_empty_param(self):
        # Arrange
        with open('test_data/get_alerts_empty_param_query.json', 'r') as file:
            expected_search_query = json.load(file)
        with open('test_data/get_alerts_empty_param_response.json', 'r') as file:
            search_response = json.load(file)
        with open('test_data/get_alerts_empty_param_result.json', 'r') as file:
            expected_result = json.load(file)

        self.connector._make_search_call = MagicMock(return_value=(True, search_response))
        param = {}
        action_result = ActionResult(param)
        self.connector.add_action_result = MagicMock(return_value=action_result)

        # Act
        status = self.connector._handle_get_alerts(param)
        actual_result = action_result.get_data()

        # Assert
        self.connector._make_search_call.assert_called_once_with(
            action_result,
            query=expected_search_query,
            page=1,
            count=VDSP_MAX_ALERTS
        )
        self.assertTrue(status)
        self.assertEqual(actual_result, expected_result, 'handle_get_alerts returns unexpected result.')

    def test_handle_get_alerts(self):
        # Arrange
        with open('test_data/get_alerts_query.json', 'r') as file:
            expected_search_query = json.load(file)
        with open('test_data/get_alerts_response.json', 'r') as file:
            search_response = json.load(file)
        with open('test_data/get_alerts_result.json', 'r') as file:
            expected_result = json.load(file)

        self.connector._make_search_call = MagicMock(return_value=(True, search_response))
        param = {
            'page': 2,
            'max_results': VDSP_MAX_ALERTS,
            'descending_order': False,
            'threat_model_name': 'Capture Access request for varadm,Capture Account authentication for varadm,Capture SYSTEM',
            'alert_status': 'New,Closed',
            'end_time': '2023-12-30T13:59:00+02:00',
            'start_time': '2023-12-01T13:00:00+02:00',
            'alert_severity': 'High, Low, Medium',
            'device_name': 'dev3cf41col01,dev3cf41dh',
            'user_name': 'varadm,SYSTEM',
            'last_days': '2'
        }
        action_result = ActionResult(param)
        self.connector.add_action_result = MagicMock(return_value=action_result)

        # Act
        status = self.connector._handle_get_alerts(param)
        actual_result = action_result.get_data()

        # Assert
        self.connector._make_search_call.assert_called_once_with(
            action_result,
            query=expected_search_query,
            page=2,
            count=VDSP_MAX_ALERTS
        )
        self.assertTrue(status)
        self.assertEqual(actual_result, expected_result, 'handle_get_alerts returns unexpected result.')
        action_result = ActionResult(param)
        self.connector.add_action_result = MagicMock(return_value=action_result)

    def test_handle_get_alerted_events(self):
        with open('test_data/get_alerted_events_query.json', 'r') as file:
            expected_search_query = json.load(file)
        with open('test_data/get_alerted_events_response.json', 'r') as file:
            search_response = json.load(file)
        with open('test_data/get_alerted_events_result.json', 'r') as file:
            expected_result = json.load(file)

        self.connector._make_search_call = MagicMock(return_value=(True, search_response))
        param = {
            'alert_id': 'EE53B604-087A-499C-88F5-7E97ABA5BD9E,A08C35C2-731A-4EA1-B350-11204EACA972'
        }
        action_result = ActionResult(param)
        self.connector.add_action_result = MagicMock(return_value=action_result)

        # Act
        status = self.connector._handle_get_alerted_events(param)
        actual_result = action_result.get_data()

        # Assert
        self.connector._make_search_call.assert_called_once_with(
            action_result,
            query=expected_search_query,
            page=1,
            count=VDSP_MAX_ALERTED_EVENTS
        )
        self.assertTrue(status)
        self.assertEqual(actual_result, expected_result, 'handle_get_alerted_events returns unexpected result.')

    def test_handle_update_alert_status(self):
        self.connector._make_rest_call = MagicMock()
        param = {
            'alert_id': '232c60e4-0f74-4f86-998b-8752a41f7910,176ee376-252c-44e0-a2d6-f8c4443ddec1',
            'status': 'new'
        }
        action_result = ActionResult(param)
        self.connector.add_action_result = MagicMock(return_value=action_result)
        json_data = {
            'AlertGuids': ['232c60e4-0f74-4f86-998b-8752a41f7910', '176ee376-252c-44e0-a2d6-f8c4443ddec1'],
            'closeReasonId': CLOSE_REASONS['none'],
            'statusId': ALERT_STATUSES['new']
        }

        status = self.connector._handle_update_alert_status(param)

        self.connector._make_rest_call.assert_called_once_with(
            action_result, VDSP_UPDATE_ALET_STATUS_ENDPOINT, method='POST', json=json_data
        )
        self.assertTrue(status)

    def test_handle_close_alert(self):
        self.connector._make_rest_call = MagicMock()
        param = {
            'alert_id': '232c60e4-0f74-4f86-998b-8752a41f7910,176ee376-252c-44e0-a2d6-f8c4443ddec1',
            'close_reason': 'resolved'
        }
        action_result = ActionResult(param)
        self.connector.add_action_result = MagicMock(return_value=action_result)
        json_data = {
            'AlertGuids': ['232c60e4-0f74-4f86-998b-8752a41f7910', '176ee376-252c-44e0-a2d6-f8c4443ddec1'],
            'closeReasonId': CLOSE_REASONS['resolved'],
            'statusId': ALERT_STATUSES['closed']
        }

        status = self.connector._handle_close_alert(param)

        self.connector._make_rest_call.assert_called_once_with(
            action_result, VDSP_UPDATE_ALET_STATUS_ENDPOINT, method='POST', json=json_data
        )
        self.assertTrue(status)


if __name__ == '__main__':
    unittest.main()
