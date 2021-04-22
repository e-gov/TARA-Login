var gulp = require('gulp');
var sass = require('gulp-sass');
var concat = require('gulp-concat');
var sourcemaps = require('gulp-sourcemaps');
var autoprefixer = require('gulp-autoprefixer');
var uglify = require('gulp-uglify');
var pump = require('pump');
var browserSync = require('browser-sync').create();
var imagemin = require('gulp-imagemin');

var config;
config = {
  SRC: {
    ICO: './favicon.ico',
    IMG: './assets/**/*',
    FONTS: './fonts/**/*',
    SASS: './styles/**/*.scss',
    JS_MAIN: './scripts/main/**/*.js',
    JS_FORM: './scripts/form/**/*.js',
    JS_GENERAL: './scripts/general/**/*.js',
    JS_LEGALPERSON: './scripts/legalperson/**/*.js'
  },
  DEST: {
    ICO: '../src/main/resources/static/TARA2',
    IMG: '../src/main/resources/static/TARA2/assets/',
    FONTS: '../src/main/resources/static/TARA2/fonts/',
    CSS: '../src/main/resources/static/TARA2/styles/',
    JS: '../src/main/resources/static/TARA2/scripts/'
  }
}

//
// BUILDERS

// Minify images
gulp.task('build:images', function () {
  return gulp
    .src(config.SRC.IMG)
    .pipe(imagemin())
    .pipe(gulp.dest(config.DEST.IMG))
    .pipe(browserSync.stream())
});
gulp.task('build:favicon', function () {
  return gulp
    .src(config.SRC.ICO)
    .pipe(imagemin())
    .pipe(gulp.dest(config.DEST.ICO))
    .pipe(browserSync.stream())
});

// Copy fonts
gulp.task('build:fonts', function () {
  return gulp
    .src(config.SRC.FONTS)
    .pipe(gulp.dest(config.DEST.FONTS))
});

// Sass to CSS
gulp.task('build:css', function() {
  return gulp
    .src(config.SRC.SASS)
    .pipe(sourcemaps.init())
    .pipe(sass({outputStyle: 'compressed'})
    .on('error', sass.logError))
    .pipe(autoprefixer())
    .pipe(concat('main.css'))
    .pipe(gulp.dest(config.DEST.CSS))
    .pipe(browserSync.stream())
});

// Build js
gulp.task('build:js_main', function(cb) {
  pump([
    gulp.src([config.SRC.JS_GENERAL, config.SRC.JS_MAIN]),
    uglify(),
    concat('main.js'),
    gulp.dest(config.DEST.JS),
    browserSync.stream()
    ],
    cb
    );
});
gulp.task('build:js_form', function(cb) {
  pump([
    gulp.src(config.SRC.JS_FORM),
    uglify(),
    gulp.dest(config.DEST.JS),
    browserSync.stream()
    ],
    cb
    );
});
gulp.task('build:js_legalperson', function(cb) {
  pump([
    gulp.src([config.SRC.JS_GENERAL, config.SRC.JS_LEGALPERSON]),
    uglify(),
    concat('legalperson.js'),
    gulp.dest(config.DEST.JS),
    browserSync.stream()
    ],
    cb
    );
});


// Gulp build
gulp.task('build', gulp.series('build:images', 'build:favicon', 'build:fonts', 'build:css', 'build:js_main', 'build:js_form', 'build:js_legalperson'), function(done) {
});
