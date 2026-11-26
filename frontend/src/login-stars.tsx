import {useEffect,useRef} from 'react';

/** Decorative star trails stay behind the form and stop when the tab is hidden. */
export function LoginStars(){
  const canvasRef=useRef<HTMLCanvasElement>(null);
  useEffect(()=>{
    const canvas=canvasRef.current;
    if(!canvas)return;
    const context=canvas.getContext('2d');
    if(!context)return;
    const motion=window.matchMedia('(prefers-reduced-motion: reduce)');
    let width=1,height=1,frame=0,last=0;
    const stars=Array.from({length:150},()=>({
      angle:Math.random()*Math.PI*2,
      depth:Math.random(),
      speed:.08+Math.random()*.12,
      brightness:.2+Math.random()*.5
    }));
    function resize(){
      width=canvas!.clientWidth;height=canvas!.clientHeight;
      const ratio=Math.min(window.devicePixelRatio||1,2);
      canvas!.width=Math.round(width*ratio);
      canvas!.height=Math.round(height*ratio);
      context!.setTransform(ratio,0,0,ratio,0,0);
      draw(0);
    }
    function draw(delta:number){
      context!.clearRect(0,0,width,height);
      const radius=Math.hypot(width,height)*.65;
      for(const star of stars){
        star.depth=(star.depth+delta*star.speed)%1;
        const distance=30+star.depth*star.depth*radius;
        const length=motion.matches?1:2+Math.pow(star.depth,3)*65;
        const dx=Math.cos(star.angle),dy=Math.sin(star.angle);
        context!.strokeStyle=`rgba(91,223,210,${star.brightness*star.depth})`;
        context!.lineWidth=.5+star.depth*1.2;
        context!.beginPath();
        context!.moveTo(width/2+dx*distance,height/2+dy*distance);
        context!.lineTo(width/2+dx*(distance+length),height/2+dy*(distance+length));
        context!.stroke();
      }
    }
    function animate(time:number){
      draw(last?Math.min((time-last)/1000,.05):0);
      last=time;
      frame=requestAnimationFrame(animate);
    }
    function update(){
      cancelAnimationFrame(frame);last=0;
      if(!document.hidden&&!motion.matches)frame=requestAnimationFrame(animate);
      else draw(0);
    }
    resize();update();
    window.addEventListener('resize',resize);
    document.addEventListener('visibilitychange',update);
    motion.addEventListener('change',update);
    return()=>{
      cancelAnimationFrame(frame);
      window.removeEventListener('resize',resize);
      document.removeEventListener('visibilitychange',update);
      motion.removeEventListener('change',update);
    };
  },[]);
  return <canvas ref={canvasRef} className="login-stars" aria-hidden="true"/>;
}
