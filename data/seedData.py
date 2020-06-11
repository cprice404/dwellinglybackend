from db import db
from models.user import UserModel
from models.property import PropertyModel
from models.tenant import TenantModel
from models.revoked_tokens import RevokedTokensModel
from models.emergency_contact import EmergencyContactModel


def seedData():
    user = UserModel(email="user1@dwellingly.org", role="admin", firstName="user1", lastName="tester", password="1234", archived=0)
    db.session.add(user)
    user = UserModel(email="user2@dwellingly.org", role="admin", firstName="user2", lastName="tester", password="1234", archived=0)
    db.session.add(user)
    user = UserModel(email="user3@dwellingly.org", role="admin", firstName="user3", lastName="tester", password="1234", archived=0)
    db.session.add(user)
    user = UserModel(email="MisterSir@dwellingly.org", role="property-manager", firstName="Mr.", lastName="Sir", password="1234", archived=0)
    db.session.add(user)
    user = UserModel(email="user3@dwellingly.org", role="property-manager", firstName="Gray", lastName="Pouponn", password="1234", archived=0)
    db.session.add(user)

    newProperty = PropertyModel(name="test1", address="123 NE FLanders St", unit="5", city="Portland", state="OR", zipcode="97207", propertyManager=5, tenants=3, dateAdded="2020-04-12", archived=0)
    db.session.add(newProperty)
    newProperty = PropertyModel(name="Meerkat Manor", address="Privet Drive", unit="2", city="Portland", state="OR", zipcode="97207", propertyManager=4, tenants=6, dateAdded="2020-04-12", archived=0)
    db.session.add(newProperty)
    newProperty = PropertyModel(name="The Reginald", address="Aristocrat Avenue", unit="3", city="Portland", state="OR", zipcode="97207", propertyManager=5, tenants=4, dateAdded="2020-04-12", archived=0)
    db.session.add(newProperty)

    newTenant = TenantModel(firstName="Renty", lastName="McRenter", phone="800-RENT-ALOT", propertyID=1, staffIDs=[1, 2])
    db.session.add(newTenant)
    newTenant = TenantModel(firstName="Soho", lastName="Muless", phone="123-123-0000", propertyID=2, staffIDs=[])
    db.session.add(newTenant)
    newTenant = TenantModel(firstName="Starvin", lastName="Artist", phone="123-123-1111", propertyID=2, staffIDs=[])
    db.session.add(newTenant)

    revokedToken = RevokedTokensModel(jti="855c5cb8-c871-4a61-b3d8-90249f979601")
    db.session.add(revokedToken)

    emergencyContact = EmergencyContactModel(name="Narcotics Anonymous", contact_numbers=[{"number": "503-345-9839"}])
    db.session.add(emergencyContact)
    emergencyContact = EmergencyContactModel(name="Washington Co. Crisis Team", contact_numbers=[{"number": "503-291-9111", "numtype": "Call"}, {"number": "503-555-3321", "numtype": "Text"}], description="Suicide prevention and referrals")
    db.session.add(emergencyContact)
    emergencyContact = EmergencyContactModel(name="Child Abuse/Reporting", contact_numbers=[{"number": "503-730-3100"}])
    db.session.add(emergencyContact)

    db.session.commit()

