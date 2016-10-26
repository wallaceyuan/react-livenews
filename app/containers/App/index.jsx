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
    color    : 'blue',
    newsList : []
  }
  componentWillMount(){
    var that = this
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

    var scrollEvent = "onscroll" in document.documentElement ? "scroll":"touchmove" ;
    $('.more_btn_loading').css('display','block');
    $(window).on('touchmove',function(){
      //that._timeBand();
    });
/*    $(window).on('swipeDown', function(){
    if(b.isclose == '0'){
      var rosHeight = $('.roseLive_head_con ').height();
      var vd = viewData();
      if(vd.scrollTop < rosHeight){
        if(b.done){
          app._incData('down');
        }
      }
    }
  });*/
    $(window).on(scrollEvent, function(){
        var ret = fuc.util._initScrollEnd(254)
        if(ret){
          ret.then((data)=>{
            var olddata = that.state.newsList
            var join = olddata.concat(data.reverse());
            that.setState({
              newsList:join
            })
          })
        }
    });
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
