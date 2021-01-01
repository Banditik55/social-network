const gulp = require('gulp')
const sass = require('gulp-sass')
const browserSync = require('browser-sync').create()
const saveCssTo = './public/css'
const scssPath = './scss/*.scss'
const htmlPath = './pages/*.html'

function style () {
	return gulp.src(scssPath)
		.pipe(sass())
		.pipe(gulp.dest(saveCssTo))
		.pipe(browserSync.stream())
}
gulp.watch(scssPath, style)

function watch () {
	browserSync.init({
		server: {
			baseDir: './'
		}
	})
	gulp.watch(scssPath, style)
	gulp.watch(htmlPath).on('change', browserSync.reload)
}

exports.style = style
exports.watch = watch