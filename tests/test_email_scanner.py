
import unittest
from unittest.mock import Mock
from email_scanner import analyze_email_body

class TestEmailScanner(unittest.TestCase):

    def test_link_scanning(self):
        """Test that suspicious links are correctly identified in the email body."""
        email = Mock()
        email.body = '''
        This is a test email with a suspicious link: 
        <a href="http://evil-domain.com/malicious-script">Click here!</a>
        And another one: <a href='https://phishing-site.org/login'>Login here</a>
        '''
        
        alerts = analyze_email_body(email)
        
        self.assertEqual(len(alerts), 1)
        self.assertIn("Found links in email", alerts[0])
        self.assertIn("http://evil-domain.com/malicious-script", alerts[0])
        self.assertIn("https://phishing-site.org/login", alerts[0])

    def test_no_links(self):
        """Test that no alerts are generated for an email with no links."""
        email = Mock()
        email.body = "This is a clean email with no links."
        
        alerts = analyze_email_body(email)
        
        self.assertEqual(len(alerts), 0)

if __name__ == '__main__':
    unittest.main()
