import React, { Component } from 'react';
import { MyComponent , Header, TimeBar, Content } from '../../components';

import fuc from '../../util/helper.jsx'
import jsonp from '../../util/jsonp.js'
import './index.css';
import $ from 'jquery'
const url = 'http://api.kankanews.com/kkweb/kkstu/cast/'

class Compse extends Component {
  render(){
    var props = this.props
    return (
      <div>
        <Header data={props.data.studio} />
        <TimeBar />
        <Content data={props}/>
      </div>
    )
  }
}

class App extends Component {
  constructor(props) {
    super(props);
  }
  state = {
    data: '',
    color:'blue'
  }
  componentWillMount(){
    var timestamp = Date.parse(new Date());
    var color = this.state.color
    fuc.getData(254).then((data) => {
      $('.mask').css('display','none');
      $('.contentWrapper').css('display','block');
      if(data.studio.color == 0){
        color = 'red'
      }
      if(data.studio.color == 1){
        color = 'blue'
      }
      if(data.studio.color == 2){
        color = 'gry'
      }
      this.setState({
        color: color,
        data:data
      })
      $('.contentWrapper').addClass(color)
    });
  }
  componentDidMount(){
    console.log('componentDidMount');
  }
  render() {
    return (
      <Compse data={this.state.data} color={this.state.color}/>
    )
  }
}

export default App;
