from datetime import datetime
import decimal

from sqlalchemy import Column, DateTime, Integer, String, Float, Table, ForeignKey
from sqlalchemy.orm import relationship

from gk_nessus.base import Base


def alchemy_encoder(obj):
    """JSON encoder function for SQLAlchemy special classes."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, decimal.Decimal):
        return float(obj)


association_table = Table('association', Base.metadata,
                          Column('plugin_id', Integer, ForeignKey('plugins.id')),
                          Column('cve_id', Integer, ForeignKey('cves.id')))


class Plugin(Base):
    __tablename__ = 'plugins'

    id = Column(Integer, primary_key=True, nullable=False)
    modified = Column(DateTime)
    published = Column(DateTime)
    score_value = Column(Float, nullable=False)
    title = Column(String(1000), nullable=False)

    cve_list = relationship("CVE", secondary='association', cascade="all, delete, save-update", lazy='joined')

    def __repr__(self):
        return "<Plugin(" \
               "id='%s', " \
               "modified='%s', " \
               "published='%s', " \
               "score_value='%s', " \
               "title='%s', " \
               "cve_list='%s')>" % (
                   self.id,
                   self.modified,
                   self.published,
                   self.score_value,
                   self.title,
                   self.cve_list)

    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            'PluginID': self.id,
            'modified': alchemy_encoder(self.modified),
            'published': alchemy_encoder(self.published),
            'score': self.score_value,
            'title': self.title,
            'cvelist': [cve.serialize() for cve in self.cve_list],
        }
