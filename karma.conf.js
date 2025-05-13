// Karma configuration
// Generated on Wed Dec 07 2016 14:40:28 GMT-0800 (PST)

module.exports = function(config) {
    config.set({

        // base path that will be used to resolve all patterns (eg. files,
        // exclude)
        basePath: '',

        // frameworks to use
        // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
        frameworks: [ 'jasmine', 'webpack' ],

        // list of files / patterns to load in the browser
        files: [
            {pattern: 'node_modules/onnxruntime-web/dist/*', watched: false, included: false, served: true, nocache: false},
            {pattern: 'modules/RTC/models/*', watched: false, included: false, served: true, nocache: false},
            {pattern: 'modules/RTC/*', watched: false, included: false, served: true, nocache: false},
            'node_modules/core-js/index.js',
            'node_modules/jquery/dist/jquery.slim.min.js',
            './modules/**/*.spec.js',
            './modules/**/*.spec.ts',
            './service/**/*.spec.ts',
            './*.spec.ts'
        ],

        // list of files to exclude
        exclude: [
        ],

        // preprocess matching files before serving them to the browser
        // available preprocessors:
        //  https://npmjs.org/browse/keyword/karma-preprocessor
        preprocessors: {
            'node_modules/core-js/**': [ 'webpack' ],
            './**/*.spec.js': [ 'webpack', 'sourcemap' ],
            './**/*.spec.ts': [ 'webpack', 'sourcemap' ]
        },

        // test results reporter to use
        // possible values: 'dots', 'progress'
        // available reporters: https://npmjs.org/browse/keyword/karma-reporter
        reporters: [ 'progress' ],

        proxies: {
            "/libs/" : "/base/modules/RTC/", 
            "/libs/dist/" : "/base/node_modules/onnxruntime-web/dist/",
            "/libs/models/" : "/base/modules/RTC/models/",
          },

        // web server port
        port: 9876,

        // enable / disable colors in the output (reporters and logs)
        colors: true,

        // level of logging
        // possible values: config.LOG_DISABLE || config.LOG_ERROR ||
        //  config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
        logLevel: config.LOG_INFO,

        // enable / disable watching file and executing tests whenever
        // any file changes
        autoWatch: false,

        // start these browsers
        // available browser launchers:
        // https://npmjs.org/browse/keyword/karma-launcher
        browsers: [ 'ChromeHeadless' ],


        browserDisconnectTimeout : 20000,
        // Continuous Integration mode
        // if true, Karma captures browsers, runs the tests and exits
        singleRun: true,

        webpack: require('./webpack-shared-config')(false /* minimize */, false /* analyzeBundle */)
    });
};
