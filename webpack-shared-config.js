/* global __dirname */

const { execSync } = require('child_process');
const path = require('path');
const process = require('process');
const { IgnorePlugin, ProvidePlugin } = require('webpack');
const { BundleAnalyzerPlugin } = require('webpack-bundle-analyzer');

const devNull = process.platform === 'win32' ? 'nul' : '/dev/null';
const commitHash = process.env.LIB_JITSI_MEET_COMMIT_HASH
    || execSync(`git rev-parse --short HEAD 2>${devNull} || echo development`)
        .toString()
        .trim();

module.exports = (minimize, analyzeBundle) => {
    return {
        experiments: {
            topLevelAwait: true
        },
        // The inline-source-map is used to allow debugging the unit tests with Karma
        devtool: minimize ? 'source-map' : 'inline-source-map',
        resolve: {
            alias: {
                'jquery': require.resolve('jquery/dist/jquery.slim.min.js')
            },
            extensions: [ '', '.js', '.ts' ]
        },
        mode: minimize ? 'production' : 'development',
        module: {
            rules: [ {
                // Version this build of the lib-jitsi-meet library.

                loader: 'string-replace-loader',
                options: {
                    flags: 'g',
                    replace: commitHash,
                    search: '{#COMMIT_HASH#}'
                },
                test: path.join(__dirname, 'JitsiMeetJS.ts')
            }, {
                // Transpile ES2015 (aka ES6) to ES5.

                loader: 'babel-loader',
                options: {
                    presets: [
                        [
                            '@babel/preset-env',

                            // Tell babel to avoid compiling imports into CommonJS
                            // so that webpack may do tree shaking.
                            {
                                modules: false,

                                // Specify our target browsers so no transpiling is
                                // done unnecessarily. For browsers not specified
                                // here, the ES2015+ profile will be used.
                                targets: {
                                    chrome: 80,
                                    electron: 10,
                                    firefox: 68,
                                    safari: 14
                                }
                            }
                        ],
                        '@babel/preset-typescript'
                    ]
                },
                test: /\.(js|ts)$/
            } ]
        },
        node: {
            // Allow the use of the real filename of the module being executed. By
            // default Webpack does not leak path-related information and provides a
            // value that is a mock (/index.js).
            __filename: true
        },
        optimization: {
            concatenateModules: minimize
        },
        output: {
            filename: `[name]${minimize ? '.min' : ''}.js`,
            sourceMapFilename: `[name].${minimize ? 'min' : 'js'}.map`
        },
        performance: {
            hints: minimize ? 'error' : false,
            maxAssetSize: 1.60 * 1024 * 1024,
            maxEntrypointSize: 1.60 * 1024 * 1024
        },
        plugins: [
            new IgnorePlugin({ resourceRegExp: /^(@xmldom\/xmldom|ws)$/ }),
            analyzeBundle
                && new BundleAnalyzerPlugin({
                    analyzerMode: 'disabled',
                    generateStatsFile: true
                }),
            !minimize
                && new ProvidePlugin({
                    process: require.resolve('process/browser')
                })
        ].filter(Boolean)
    };
};
