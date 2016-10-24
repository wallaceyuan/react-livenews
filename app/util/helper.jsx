import axios from 'axios';
import $ from 'jquery'

const url = 'http://api.kankanews.com/kkweb/kkstu/cast/'

function getData(id) {
  var timestamp = Date.parse(new Date());
  let u = url+id+'.json?ord=asc?'+timestamp+'&jsoncallback=?';
  return $.getJSON(u)
}
module.exports = {
  getData: getData
}
