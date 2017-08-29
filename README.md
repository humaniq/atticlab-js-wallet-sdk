# JS Wallet SDK

**Create api object**

```js
var api = require('js-wallet-sdk');

var WalletApi = new api({
    host: keyserver_host
});
```


#### `Create wallet`
```js
WalletApi.create({
    keypair: accountKeypair,
    password: password,
    // You can signup using any of these fields
    phone: '+380xxxxxxxxx',
    email: 'xxx@xxx.com'
}).then(wallet => {
    // this is where you get your wallet object
});
```

#### `Get wallet`
```js
WalletApi.get({
    password: 'your_password',
    // You can login using any of these fields
    phone: '+380xxxxxxxxx',
    email: 'xxx@xxx.com'
    // These fields are optional
    sms_code: 'xxxxxx' // TFA code from SMS
    totp_code: 'xxxxxx' // TFA code using google authenticator
}).then(wallet => {
    // this is where you get your wallet object
});
```

## `Wallet methods`
#### `Two-factor auth using totp`
Returns secret key to paste into your google auth or freeotp app
```js
wallet.enableTotp()
```

After you enabled top, you need to activate it
```js
wallet.activateTotp('code_from_app')
```

You can as well disable it
```js
wallet.disableTotp('code_from_app')
```
