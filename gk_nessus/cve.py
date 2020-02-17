from sqlalchemy import Column, String, Integer
from gk_nessus.base import Base


class CVE(Base):
    __tablename__ = 'cves'

    id = Column(Integer, primary_key=True, nullable=False)
    str_id = Column(String(255), nullable=False)
    cve = Column(String(255), nullable=False)

    def __repr__(self):
        return "<CVE(id='%s', str_id='%s', cve='%s')>" % (self.id, self.str_id, self.cve)

    @property
    def serialize(self):
        """Return object data in easily serializable format"""
        return {
            'id': self.id,
            'str_id': self.str_id,
            'cve': self.cve,
        }

