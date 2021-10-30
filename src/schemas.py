from src.models import Person
from src.main import ma


class PersonSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Person

    id = ma.auto_field()
    first_name = ma.auto_field()
    last_name = ma.auto_field()
    level = ma.auto_field()

class CreatePersonSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Person

    id = ma.auto_field()
    first_name = ma.auto_field()
    last_name = ma.auto_field()
    phone_number = ma.auto_field()
    email_address = ma.auto_field()
    birth_date = ma.auto_field()
    address = ma.auto_field()
    level = ma.auto_field()
