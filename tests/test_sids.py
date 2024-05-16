import unittest
import json
from src.sids.sids_main import app


class TestSIDS(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_predict(self):
        sample_data = {"feature1": 1, "feature2": 0}
        response = self.app.post(
            "/predict", data=json.dumps(sample_data), content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("prediction", response.get_json())

    def test_train(self):
        sample_data = [
            {"feature1": 1, "feature2": 0, "label": 0},
            {"feature1": 0, "feature2": 1, "label": 1},
        ]
        response = self.app.post(
            "/train", data=json.dumps(sample_data), content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "model trained and saved")


if __name__ == "__main__":
    unittest.main()
