from flask import Flask, render_template, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import CloudInstance, SecurityAlert, get_db_url
from datetime import datetime

app = Flask(__name__, 
    template_folder='frontend/templates',
    static_folder='frontend/static')

# יצירת חיבור למסד
engine = create_engine(get_db_url())
Session = sessionmaker(bind=engine)

@app.route('/')
def dashboard():
    """דף הבית - Dashboard"""
    session = Session()
    
    # קבלת נתונים מהמסד
    instances = session.query(CloudInstance).all()
    alerts = session.query(SecurityAlert).filter_by(status='open').all()
    
    # סטטיסטיקות
    stats = {
        'total_instances': len(instances),
        'running': len([i for i in instances if i.state == 'running']),
        'stopped': len([i for i in instances if i.state == 'stopped']),
        'open_alerts': len(alerts),
        'critical_alerts': len([a for a in alerts if a.severity == 'critical']),
        'high_alerts': len([a for a in alerts if a.severity == 'high'])
    }
    
    session.close()
    
    return render_template('dashboard.html', 
                         instances=instances, 
                         alerts=alerts,
                         stats=stats)

@app.route('/api/stats')
def get_stats():
    """API endpoint לסטטיסטיקות"""
    session = Session()
    
    instances = session.query(CloudInstance).all()
    alerts = session.query(SecurityAlert).filter_by(status='open').all()
    
    data = {
        'instances': {
            'total': len(instances),
            'running': len([i for i in instances if i.state == 'running']),
            'stopped': len([i for i in instances if i.state == 'stopped'])
        },
        'alerts': {
            'total': len(alerts),
            'by_severity': {
                'critical': len([a for a in alerts if a.severity == 'critical']),
                'high': len([a for a in alerts if a.severity == 'high']),
                'medium': len([a for a in alerts if a.severity == 'medium']),
                'low': len([a for a in alerts if a.severity == 'low'])
            }
        },
        'timestamp': datetime.now().isoformat()
    }
    
    session.close()
    return jsonify(data)

if __name__ == '__main__':
    print("=" * 50)
    print("🚀 Starting CIRA Dashboard")
    print("📍 URL: http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)
