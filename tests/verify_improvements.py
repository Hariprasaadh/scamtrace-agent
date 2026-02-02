
import sys
import os
import asyncio

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

print("Testing imports...")
try:
    from app.main import app
    print("SUCCESS: app.main imported")
except ImportError as e:
    print(f"ERROR: Failed to import app.main: {e}")
    sys.exit(1)

try:
    from app.services import agent, extractor, personas
    print("SUCCESS: app.services imported")
except ImportError as e:
    print(f"ERROR: Failed to import services: {e}")
    sys.exit(1)

print("\nTesting Persona Logic...")
scam_msg = "I am calling from Amazon, your job offer is ready. Salary 5000 per day."
persona = personas.get_persona(scam_msg)
print(f"Input: '{scam_msg}'")
print(f"Selected Persona: {persona['name']}")
if persona['name'] != "Rahul/Priya":
    print("FAILURE: Did not select 'desperate_youth' persona for job scam")
    sys.exit(1)
print("SUCCESS: Persona selection works")

print("\nTesting Extractor Logic...")
scam_text = "Pay to my upi: scammer@okaxis or transfer to Account 123456789012IFSC: SBIN0001234"
intel = extractor.extract_from_message(scam_text)
print(f"Input: '{scam_text}'")
print(f"Extracted UPI: {intel.upiIds}")
print(f"Extracted Bank: {intel.bankAccounts}")

if "scammer@okaxis" not in intel.upiIds:
    print("FAILURE: Failed to extract UPI")
    sys.exit(1)

if "123456789012" not in intel.bankAccounts:
    print("FAILURE: Failed to extract Bank Account")
    sys.exit(1)

print("\nALL CHECKS PASSED")
