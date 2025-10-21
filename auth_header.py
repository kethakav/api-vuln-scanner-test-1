def sendingRequest(msg, initiator, helper):
    token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NjEwMjE0OTAsImlhdCI6MTc2MTAyMTQzMCwic3ViIjoibmFtZTEifQ.nlhVdyINlD40OSOemrjiCyxAaEQHFYW0WQ4qpw3suog'
    msg.getRequestHeader().setHeader('Authorization', f'Bearer {token}')