var webpack = require("webpack");

module.exports = {
    entry: './index.js',
    output: {
        path: './dist/',
        library: 'SmartWallet',
        filename: 'js-wallet-sdk.js',
    },
    module: {
        loaders: [{
            test: /\.js$/,
            exclude: /node_modules/,
            loader: 'babel-loader',
            options: {
                'presets': ['es2015']
            }
        }]
    },
    node: {
        fs: 'empty'
    },
    externals: {
        bindings: true
    }
}
