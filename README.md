### Check your SANity

> A recursive SAN based domain enumeration tool

![Screenshot 2024-08-17 at 6 55 42 PM](https://github.com/user-attachments/assets/b3d3cb2b-3162-4c97-ac83-d0b54fb1a478)

> Where can I use this tool?

For security reasons, I'm not running a public SANity server atm. If you feel so compelled, you can set up a public server for people to use.

To start a SANity server, navigate to the `ROCKET` directory and run `cargo run --release`. 
This will start a server on port 8000. 
Changing ports at runtime is not currently supported, change the hardcoded value in the source code.

SANity has a standalone frontend project, seperate from the server. 
Navigate to `WWW` and run the `dev` alias in the package.json. For example, `yarn run dev`, or `npm run dev`. 
Make sure to install the dependancies first; `yarn install`, `npm install`.

You can see a static example scan of google.com located at [https://notmysql.hackclub.app/SAN.html](https://notmysql.hackclub.app/SAN.html)
