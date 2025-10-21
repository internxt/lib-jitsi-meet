// Karma configuration
// Generated on Wed Dec 07 2016 14:40:28 GMT-0800 (PST)

module.exports = function(config) {
    config.set({
        // enable / disable watching file and executing tests whenever
        // any file changes
        autoWatch: false,

        // base path that will be used to resolve all patterns (eg. files,
        // exclude)
        basePath: '',

        // start these browsers
        // available browser launchers:
        // https://npmjs.org/browse/keyword/karma-launcher
        browsers: [ 'ChromeHeadless' ],

        // enable / disable colors in the output (reporters and logs)
        colors: true,

        // list of files to exclude
        exclude: [
        ],

        // list of files / patterns to load in the browser
        files: [
            {
                pattern: 'models/RTC/*',
                watched: false,
                included: false,
                served: true,
                nocache: false
            },
            {
                pattern: 'wasm/RTC/*',
                watched: false,
                included: false,
                served: true,
                nocache: false
            },
            'node_modules/core-js/index.js',
            './modules/**/*.spec.js',
            './modules/**/*.spec.ts',
            './service/**/*.spec.ts',
            './*.spec.ts',
            {
                pattern:
                    'node_modules/vodozemac-wasm/javascript/pkg/vodozemac_bg.wasm',
                included: false,
                served: true,
                watched: false
            },
            './tests/*.spec.js',
            './tests/*.spec.ts'
        ],
        mime: {
            'application/wasm': [ 'wasm' ]
        },
        experiments: {
            asyncWebAssembly: true
        },
        module: {
            rules: [
                {
                    test: /\.wasm$/,
                    type: 'asset/resource' // emit as file, returns URL
                }
            ]
        },
        resolve: {
            extensions: [ '.ts', '.js', '.wasm' ]
        },

        // frameworks to use
        // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
        frameworks: [ 'jasmine', 'webpack' ],

        // level of logging
        // possible values: config.LOG_DISABLE || config.LOG_ERROR ||
        //  config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
        logLevel: config.LOG_INFO,

        // web server port
        port: 9876,

        // preprocess matching files before serving them to the browser
        // available preprocessors:
        //  https://npmjs.org/browse/keyword/karma-preprocessor
        preprocessors: {
            './**/*.spec.js': [ 'webpack', 'sourcemap' ],
            './**/*.spec.ts': [ 'webpack', 'sourcemap' ],
            'node_modules/core-js/**': [ 'webpack' ]
        },

        // test results reporter to use
        // possible values: 'dots', 'progress'
        // available reporters: https://npmjs.org/browse/keyword/karma-reporter
        reporters: [ 'progress' ],

        // Continuous Integration mode
        // if true, Karma captures browsers, runs the tests and exits
        singleRun: true,

        webpack: require('./webpack-shared-config')(
            false /* minimize */,
            false /* analyzeBundle */
        ),

        client: {
            args: config.grep ? [ '--grep', config.grep ] : [],
            jasmine: {
                random: false
            }
        }
    });
};
