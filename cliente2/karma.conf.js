// Karma configuration file
// See https://karma-runner.github.io/latest/config/configuration-file.html

// Usar Edge como navegador (Chromium-based) si Chrome no está instalado
process.env.CHROME_BIN = process.env.CHROME_BIN
  || 'C:\\Program Files (x86)\\Microsoft\\EdgeCore\\145.0.3800.82\\msedge.exe';

module.exports = function (config) {
  config.set({
    basePath: '',
    frameworks: ['jasmine', '@angular-devkit/build-angular'],
    plugins: [
      require('karma-jasmine'),
      require('karma-chrome-launcher'),
      require('karma-jasmine-html-reporter'),
      require('karma-coverage'),
      require('@angular-devkit/build-angular/plugins/karma')
    ],
    client: {
      jasmine: {},
      clearContext: false // leave Jasmine Spec Runner output visible in browser
    },
    jasmineHtmlReporter: {
      suppressAll: true
    },
    coverageReporter: {
      dir: require('path').join(__dirname, './coverage/protecci-n-client'),
      subdir: '.',
      reporters: [
        { type: 'html' },
        { type: 'text-summary' }
      ]
    },
    reporters: ['progress', 'kjhtml'],
    browsers: ['ChromeHeadless'],
    restartOnFileChange: true
  });
};
