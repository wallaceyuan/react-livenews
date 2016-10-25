import React, { Component } from 'react';
import {Header, TimeBar, Content } from '../../components';

import fuc from '../../util/helper.jsx'
import './index.css';
import $ from 'jquery'

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
    data     : '',
    color    :'blue',
    newsList :[]
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
        data:data,
        newsList:data.news.reverse()
      })
      $('.contentWrapper').addClass(color)
    });
    fuc.test(1476829924,254).then((data)=>{
      var olddata = this.state.newsList
      var join = olddata.concat(data.reverse());
        console.log('2s done')
      /*        console.log('new data',data.reverse())
       console.log('old data',olddata)
       console.log('join data',join)*/
      this.setState({
          newsList:join
      })
    })
  }
  componentDidMount(){

    console.log('componentDidMount');
  }
  render() {
    return (
      <Compse data={this.state.data} color={this.state.color} newsList={this.state.newsList}/>
    )
  }
}

export default App;
