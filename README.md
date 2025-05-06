# Mumble

It shares the user's secrets without the user's name. People can read all the secrets. It also generates random secrets from the secrets API.

# How to...

1. Install the npm package.
2. Create tables in PostgreSQL from the queries.sql file.
3. Create a project at [Google credentials ](https://console.cloud.google. com/projectselector2/auth/overview?inv=1&invt=AbwqGg&supportedpurview=project) and get Google's client ID, client secret and callback URL.
4. Input the credentials in the .env file.
5. Run the app.js file.
