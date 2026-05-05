# Payjoin JavaScript Bindings

Welcome to the JavaScript language bindings for the [Payjoin Dev Kit](https://payjoindevkit.org/)!

## Usage

### Install

```shell
npm install payjoin
```

### Import

For node environments:

```js
import { uniffiInitAsync, payjoin } from "payjoin";

// initialize before usage
await uniffiInitAsync();
```

For web browser environments:

```js
import * as payjoin from "payjoin/web";
// or for usage with Vite
import * as payjoin from "payjoin/web-vite";

// initialize before usage
await payjoin.uniffiInitAsync();
```

Made with [uniffi-bindgen-react-native](https://github.com/jhugman/uniffi-bindgen-react-native)
