"""
Test script for URL Analysis API
Run this to verify the endpoint is working correctly
"""

import requests
import json

API_URL = "http://localhost:8000/analyze-url"

def test_url_analysis(url):
    """Test the URL analysis endpoint"""
    print(f"\n{'='*60}")
    print(f"Testing URL: {url}")
    print(f"{'='*60}\n")
    
    try:
        response = requests.post(
            API_URL,
            json={"url": url},
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            result = response.json()
            
            print(f"✅ Status: {response.status_code} OK\n")
            print(f"URL: {result['url']}")
            print(f"Is Safe: {result['is_safe']}")
            print(f"Prediction: {result['prediction']}")
            print(f"Risk Level: {result['risk_level']}")
            print(f"\nRecommendation:")
            print(f"  {result['recommendation']}")
            
            print(f"\nFeatures Extracted:")
            for feature, value in list(result['features_extracted'].items())[:5]:
                print(f"  - {feature}: {value}")
            print(f"  ... (and {len(result['features_extracted']) - 5} more features)")
            
        else:
            print(f"❌ Error: {response.status_code}")
            print(response.text)
            
    except requests.exceptions.ConnectionError:
        print("❌ Connection Error!")
        print("Make sure the FastAPI server is running:")
        print("  cd /Users/harshraj/Desktop/Networking")
        print("  python app.py")
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    print("\n🔍 URL Analysis API Test Suite")
    print("="*60)
    
    # Test with safe URLs
    print("\n📊 Testing SAFE URLs:")
    test_url_analysis("https://www.google.com")
    test_url_analysis("https://www.github.com")
    
    # Test with potentially suspicious patterns
    print("\n\n⚠️  Testing SUSPICIOUS URLs:")
    test_url_analysis("http://192.168.1.1/login")
    test_url_analysis("https://bit.ly/test123")
    
    print("\n" + "="*60)
    print("✅ Test suite completed!")
    print("="*60 + "\n")
