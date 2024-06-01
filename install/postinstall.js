const fs = require('fs')
const path = require('path')

const packageJSON = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json')).toString())

const packageVersion = packageJSON.version
const arch = process.arch
const platform = process.platform
const nodeVersion = process.version.replace('v', '').split('.')[0]

const downloadURL = `https://github.com/boringjs/boringtun.js/releases/download/v${packageVersion}/boringtunjs-v${packageVersion}-${nodeVersion}-${platform}-${arch}.node`

const buildDir = path.join(__dirname, '..', 'build', 'lib')
const bindingsPath = path.join(buildDir, 'boringtunjs.node')

if (!fs.existsSync(bindingsPath)) {
  fs.mkdirSync(buildDir, { recursive: true })
  fetch(downloadURL)
    .then((res) => {
      if (res.status !== 200) {
        console.warn('Boringtunjs: not supported platform. Please report issue.')
      }
      return res.arrayBuffer()
    })
    .then((file) => fs.writeFileSync(bindingsPath, Buffer.from(file)))
    .catch(console.error)
}
