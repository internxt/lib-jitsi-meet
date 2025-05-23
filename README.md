# Jitsi Meet API library

You can use Jitsi Meet API to create Jitsi Meet video conferences with a custom GUI.

## Installation

- [Installation guide](doc/API.md#installation)
- [Checkout the example](doc/example)

## Building the sources

NOTE: you need Node.js >= 12 and npm >= 7

To build the library, just type:
```
npm install
npm run build
```
To lint:
```
npm run lint
```
and to run unit tests:
```
npm test
```
if you need to rebuild lib-jitsi-meet.min.js
```
npm run build
```

Both linting and units will also be done by a pre-commit hook.

## How to run and test the library locally:

To test this library, you will need <https://github.com/jitsi/jitsi-meet>. There is a pretty good tutorial in jitsi docs <https://jitsi.github.io/handbook/docs/dev-guide/dev-guide-web-jitsi-meet>.

Here is a resume of how you can run your own environment:

1. Create a folder called meet or whatever you want to call this project.
2. Clone this repository.
3. Run `cd lib-jitsi-meet` to move to the folder.
4. Run the commands below to create a link to your local library and build it.  

    ```
    npm install 
    npm link
    npm run build
    ```

5. Run `cd ..`
6. Go to <https://github.com/jitsi/jitsi-meet> and clone the repository.
7. Run `cd jitsi-meet`
8. Run `npm link lib-jitsi-meet`
    ```
    npm link lib-jitsi-meet 
    npm install
    make dev
    ```

If you want to make changes to only lib-jitsi-meet, you need to run `npm run build` and restart the `make dev` process. Otherwise, the changes you made to the library are not going to be shown in the app.

## Publishing to releases

### Step 1: Bump the version  
Update the `package.json "version"` field to the next release number (e.g. from `1.2.3` to `1.2.4`).  

### Step 2: Create a GitHub draft release
1. Go to your GitHub repo’s Releases page.
2. Click Draft a new release.
3. Tag the release with the new version (e.g. v1.2.4).
4. Title it “v1.2.4” and paste your changelog bullet list in the description.
5. Click Save draft (do not publish yet).

### Step 2: Generate the npm package
```
npm install      # ensure dependencies are up to date
npm pack         # creates a .tgz bundle (e.g. lib-jitsi-meet-1.2.4.tgz)
```
### Step 3: Generate the npm package
In your draft release on GitHub, upload the generated lib-jitsi-meet-1.2.4.tgz under Attach binaries by dropping them here or selecting them.

### Step 5: Publish the release
With the .tgz attached, click Publish release.

### Step 6: Update downstream dependency
In the internxt-meet repo’s package.json, change the lib-jitsi-meet entry to the new tarball URL:

```json
"dependencies": {
  "lib-jitsi-meet": "https://github.com/internxt/lib-jitsi-meet/releases/download/v1.2.4/lib-jitsi-meet-1.2.4.tgz",
  // … other deps …
}
```
